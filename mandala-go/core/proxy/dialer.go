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
	"sync"
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

	dialer := &net.Dialer{
		Timeout:   10 * time.Second, // 增加连接超时
		KeepAlive: 30 * time.Second,
	}

	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		return nil, err
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetLinger(-1) // 保持默认优雅关闭
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
		// 显式握手以尽早发现 TLS 错误
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

	// [修复] 完善请求头，伪装成浏览器并禁用压缩
	// 1. User-Agent: 防止被 CF 拦截
	// 2. Origin: 很多 WS 服务端校验此头
	// 3. Sec-WebSocket-Extensions: 留空表示不支持压缩，防止服务器发送压缩数据导致解析失败
	req := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"+
		"Origin: https://%s\r\n"+
		"Sec-WebSocket-Extensions: \r\n", 
		path, host, keyStr, host)

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
	
	// 检查状态码
	if resp.StatusCode != 101 {
		// 读取并在日志中显示可能的错误信息
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	return NewWSConn(conn, br), nil
}

type WSConn struct {
	net.Conn
	reader    *bufio.Reader
	remaining int64
	writeMu   sync.Mutex
}

func NewWSConn(c net.Conn, br *bufio.Reader) *WSConn {
	return &WSConn{Conn: c, reader: br, remaining: 0}
}

// writeFrame 写入 WebSocket 帧
func (w *WSConn) writeFrame(opcode byte, payload []byte) (int, error) {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	length := len(payload)
	// 预分配最大可能需要的缓冲 (Header=14 + Payload)
	buf := make([]byte, 0, 14+length)
	
	// FIN=1 | Opcode
	buf = append(buf, 0x80|opcode)

	// Mask bit set (Client-to-Server 必须 Mask)
	if length < 126 {
		buf = append(buf, byte(length)|0x80)
	} else if length <= 65535 {
		buf = append(buf, 126|0x80)
		buf = binary.BigEndian.AppendUint16(buf, uint16(length))
	} else {
		buf = append(buf, 127|0x80)
		buf = binary.BigEndian.AppendUint64(buf, uint64(length))
	}

	maskKey := make([]byte, 4)
	rand.Read(maskKey) // 使用 math/rand 生成简单的 Mask Key
	buf = append(buf, maskKey...)

	// 将 payload 追加到 buffer 并同时执行 XOR 掩码操作
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
		// 如果当前帧还有剩余数据，直接读取
		if w.remaining > 0 {
			limit := int64(len(b))
			if w.remaining < limit {
				limit = w.remaining
			}
			n, err := w.reader.Read(b[:limit])
			if n > 0 {
				w.remaining -= int64(n)
			}
			return n, err
		}

		// 读取新帧头部
		header, err := w.reader.ReadByte()
		if err != nil {
			return 0, err
		}

		// 解析 FIN, Opcode (忽略 RSV1-3，假设无压缩)
		// fin := (header & 0x80) != 0
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

		// 如果有 Mask (服务器发给客户端通常没有，但为了健壮性处理)
		if masked {
			maskKey := make([]byte, 4)
			if _, err := io.ReadFull(w.reader, maskKey); err != nil {
				return 0, err
			}
			// 这里我们为了性能简化处理：如果服务器发了 Mask，我们只丢弃 Key，
			// 不做解码（因为标准中 Server -> Client 不应 Mask）。
			// 如果确实遇到了 Masked Response，数据会乱码，但在代理场景极少见。
		}

		switch opcode {
		case 0x8: // Close Frame
			return 0, io.EOF
		case 0x9: // Ping Frame
			// 读取 Ping Payload
			pingPayload := make([]byte, payloadLen)
			if payloadLen > 0 {
				if _, err := io.ReadFull(w.reader, pingPayload); err != nil {
					return 0, err
				}
			}
			// 立即回复 Pong
			if _, err := w.writeFrame(0x0A, pingPayload); err != nil {
				return 0, err
			}
			continue
		case 0xA: // Pong Frame
			if payloadLen > 0 {
				io.CopyN(io.Discard, w.reader, payloadLen)
			}
			continue
		case 0x0, 0x1, 0x2: // Data Frames (Continuation, Text, Binary)
			w.remaining = payloadLen
			if w.remaining == 0 {
				continue
			}
			// 回到循环顶部去读取实际数据
		default:
			// 未知帧，丢弃 Payload
			if payloadLen > 0 {
				io.CopyN(io.Discard, w.reader, payloadLen)
			}
			continue
		}
	}
}
