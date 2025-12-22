package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sync" // 引入 sync 用于锁
	"time"

	"mandala/core/config"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type Dialer struct {
	Config *config.OutboundConfig
}

func NewDialer(cfg *config.OutboundConfig) *Dialer {
	return &Dialer{Config: cfg}
}

func (d *Dialer) Dial() (net.Conn, error) {
	targetAddr := fmt.Sprintf("%s:%d", d.Config.Server, d.Config.ServerPort)

	// 使用更底层的 Dialer
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return nil, err
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		// [保持] 移除 SetLinger(0)，使用默认优雅关闭
		tcpConn.SetLinger(-1)
	}

	// TLS 处理
	if d.Config.TLS != nil && d.Config.TLS.Enabled {
		tlsConfig := &tls.Config{
			ServerName:         d.Config.TLS.ServerName,
			InsecureSkipVerify: d.Config.TLS.Insecure,
			MinVersion:         tls.VersionTLS12,
		}
		if tlsConfig.ServerName == "" {
			tlsConfig.ServerName = d.Config.Server
		}

		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tls handshake failed: %v", err)
		}
		conn = tlsConn
	}

	// WebSocket 处理
	if d.Config.Transport != nil && d.Config.Transport.Type == "ws" {
		wsConn, err := d.handshakeWebSocket(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("websocket handshake failed: %v", err)
		}
		return wsConn, nil
	}

	return conn, nil
}

func (d *Dialer) handshakeWebSocket(conn net.Conn) (net.Conn, error) {
	path := d.Config.Transport.Path
	if path == "" {
		path = "/"
	}
	host := d.Config.TLS.ServerName
	if host == "" {
		host = d.Config.Server
	}

	key := make([]byte, 16)
	rand.Read(key)
	keyStr := base64.StdEncoding.EncodeToString(key)

	req := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n", path, host, keyStr)

	if d.Config.Transport.Headers != nil {
		for k, v := range d.Config.Transport.Headers {
			req += fmt.Sprintf("%s: %s\r\n", k, v)
		}
	}
	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 101 {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return NewWSConn(conn, br), nil
}

type WSConn struct {
	net.Conn
	reader    *bufio.Reader
	remaining int64
	writeMu   sync.Mutex // 增加写锁，防止 Read 里的自动 Pong 和 Write 冲突
}

func NewWSConn(c net.Conn, br *bufio.Reader) *WSConn {
	return &WSConn{Conn: c, reader: br, remaining: 0}
}

// writeFrame 封装帧发送逻辑
func (w *WSConn) writeFrame(opcode byte, payload []byte) (int, error) {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	length := len(payload)
	buf := make([]byte, 0, 14+length)
	buf = append(buf, 0x80|opcode) // FIN=1 + Opcode

	if length < 126 {
		buf = append(buf, byte(length)|0x80) // Mask bit set
	} else if length <= 65535 {
		buf = append(buf, 126|0x80)
		buf = binary.BigEndian.AppendUint16(buf, uint16(length))
	} else {
		buf = append(buf, 127|0x80)
		buf = binary.BigEndian.AppendUint64(buf, uint64(length))
	}

	maskKey := make([]byte, 4)
	rand.Read(maskKey)
	buf = append(buf, maskKey...)

	payloadStart := len(buf)
	buf = append(buf, payload...)

	for i := 0; i < length; i++ {
		buf[payloadStart+i] ^= maskKey[i%4]
	}

	if _, err := w.Conn.Write(buf); err != nil {
		return 0, err
	}
	return length, nil
}

func (w *WSConn) Write(b []byte) (int, error) {
	// 0x2 = Binary Frame
	return w.writeFrame(0x02, b)
}

func (w *WSConn) Read(b []byte) (int, error) {
	for {
		if w.remaining > 0 {
			limit := int64(len(b))
			if w.remaining < limit {
				limit = w.remaining
			}
			n, err := w.reader.Read(b[:limit])
			if n > 0 {
				w.remaining -= int64(n)
			}
			if n > 0 || err != nil {
				return n, err
			}
		}

		header, err := w.reader.ReadByte()
		if err != nil {
			return 0, err
		}

		opcode := header & 0x0F
		lenByte, err := w.reader.ReadByte()
		if err != nil {
			return 0, err
		}

		masked := (lenByte & 0x80) != 0
		payloadLen := int64(lenByte & 0x7F)

		if payloadLen == 126 {
			lenBuf := make([]byte, 2)
			if _, err := io.ReadFull(w.reader, lenBuf); err != nil {
				return 0, err
			}
			payloadLen = int64(binary.BigEndian.Uint16(lenBuf))
		} else if payloadLen == 127 {
			lenBuf := make([]byte, 8)
			if _, err := io.ReadFull(w.reader, lenBuf); err != nil {
				return 0, err
			}
			payloadLen = int64(binary.BigEndian.Uint64(lenBuf))
		}

		if masked {
			if _, err := io.CopyN(io.Discard, w.reader, 4); err != nil {
				return 0, err
			}
		}

		switch opcode {
		case 0x8: // Close
			return 0, io.EOF
		case 0x9: // Ping
			// [修复] 收到 Ping 必须回复 Pong，且携带相同的 Payload
			pingPayload := make([]byte, payloadLen)
			if payloadLen > 0 {
				if _, err := io.ReadFull(w.reader, pingPayload); err != nil {
					return 0, err
				}
			}
			// 发送 Pong (Opcode 0xA)
			if _, err := w.writeFrame(0x0A, pingPayload); err != nil {
				return 0, err
			}
			continue
		case 0xA: // Pong
			// 忽略 Pong，但需丢弃数据
			if payloadLen > 0 {
				io.CopyN(io.Discard, w.reader, payloadLen)
			}
			continue
		case 0x0, 0x1, 0x2: // Data Frames
			w.remaining = payloadLen
			if w.remaining == 0 {
				continue
			}
		default:
			// 未知帧，丢弃
			if payloadLen > 0 {
				io.CopyN(io.Discard, w.reader, payloadLen)
			}
			continue
		}
	}
}
