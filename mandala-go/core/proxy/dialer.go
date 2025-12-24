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
	"time"

	"mandala/core/config"
)

func init() {
	// 初始化随机数种子，用于 WebSocket Mask Key 和分片随机延迟
	rand.Seed(time.Now().UnixNano())
}

// [新增] FragmentConn 封装原生连接，实现数据写入时的物理分片
// 主要用于在 TLS 握手阶段（ClientHello）将数据包切碎，绕过 DPI 特征识别
type FragmentConn struct {
	net.Conn
	FragmentSize int
	processed    int // 记录已处理的字节数，通常只对握手初期的包进行分片
}

func (f *FragmentConn) Write(b []byte) (n int, err error) {
	// 如果未开启分片或已过敏感握手期（例如前 2KB），直接发送，避免影响后续速度
	if f.FragmentSize <= 0 || f.processed > 2048 {
		return f.Conn.Write(b)
	}

	written := 0
	totalLen := len(b)
	
	for written < totalLen {
		remaining := totalLen - written
		chunkSize := f.FragmentSize
		if remaining < chunkSize {
			chunkSize = remaining
		}

		// 写入切片数据
		nw, err := f.Conn.Write(b[written : written+chunkSize])
		if err != nil {
			return written, err
		}
		
		written += nw
		f.processed += nw
		
		// [关键] 在分片之间加入微小延迟，强制在网络层形成多个物理包
		if written < totalLen {
			time.Sleep(time.Millisecond * 5)
		}
	}
	return written, nil
}

type Dialer struct {
	Config *config.OutboundConfig
}

func NewDialer(cfg *config.OutboundConfig) *Dialer {
	return &Dialer{Config: cfg}
}

func (d *Dialer) Dial() (net.Conn, error) {
	targetAddr := fmt.Sprintf("%s:%d", d.Config.Server, d.Config.ServerPort)
	// 建立基础 TCP 连接
	rawConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	var conn net.Conn = rawConn

	// [功能补全] 如果配置中开启了分片且设置了有效大小，应用分片包装器
	// 注意：必须在 TLS 握手之前应用，这样 ClientHello 才能被分片
	if d.Config.Settings != nil && d.Config.Settings.Fragment && d.Config.Settings.FragmentSize > 0 {
		conn = &FragmentConn{
			Conn:         rawConn,
			FragmentSize: d.Config.Settings.FragmentSize,
		}
	}

	// 处理 TLS
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

	// 处理 WebSocket
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
	if path == "" { path = "/" }
	host := d.Config.TLS.ServerName
	if host == "" { host = d.Config.Server }

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

// WSConn 保持原有逻辑，用于处理 WebSocket 数据帧封装
type WSConn struct {
	net.Conn
	reader    *bufio.Reader
	remaining int64 
}

func NewWSConn(c net.Conn, br *bufio.Reader) *WSConn {
	return &WSConn{Conn: c, reader: br, remaining: 0}
}

func (w *WSConn) Write(b []byte) (int, error) {
	length := len(b)
	if length == 0 { return 0, nil }

	// 预估头部长度，最大 14 字节
	buf := make([]byte, 0, 14+length)
	buf = append(buf, 0x82) // Binary Frame

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
	rand.Read(maskKey)
	buf = append(buf, maskKey...)

	payloadStart := len(buf)
	buf = append(buf, b...)
	
	for i := 0; i < length; i++ {
		buf[payloadStart+i] ^= maskKey[i%4]
	}

	if _, err := w.Conn.Write(buf); err != nil {
		return 0, err
	}
	return length, nil
}

func (w *WSConn) Read(b []byte) (int, error) {
	for {
		// 1. 如果当前帧还有剩余数据，直接读取
		if w.remaining > 0 {
			limit := int64(len(b))
			if w.remaining < limit { limit = w.remaining }
			n, err := w.reader.Read(b[:limit])
			if n > 0 { w.remaining -= int64(n) }
			if n > 0 || err != nil { return n, err }
		}

		// 2. 读取新帧头部
		header, err := w.reader.ReadByte()
		if err != nil { return 0, err }
		
		opcode := header & 0x0F
		lenByte, err := w.reader.ReadByte()
		if err != nil { return 0, err }

		masked := (lenByte & 0x80) != 0
		payloadLen := int64(lenByte & 0x7F)

		if payloadLen == 126 {
			lenBuf := make([]byte, 2)
			if _, err := io.ReadFull(w.reader, lenBuf); err != nil { return 0, err }
			payloadLen = int64(binary.BigEndian.Uint16(lenBuf))
		} else if payloadLen == 127 {
			lenBuf := make([]byte, 8)
			if _, err := io.ReadFull(w.reader, lenBuf); err != nil { return 0, err }
			payloadLen = int64(binary.BigEndian.Uint64(lenBuf))
		}

		// 客户端通常不需要处理 Mask，但如果是 Masked 帧则丢弃 Mask Key
		if masked {
			if _, err := io.CopyN(io.Discard, w.reader, 4); err != nil { return 0, err }
		}

		// 处理控制帧
		switch opcode {
		case 0x8: // Close
			return 0, io.EOF
		case 0x9, 0xA: // Ping/Pong
			if payloadLen > 0 { io.CopyN(io.Discard, w.reader, payloadLen) }
			continue
		case 0x0, 0x1, 0x2: // Continuation, Text, Binary
			w.remaining = payloadLen
			if w.remaining == 0 { continue }
		default:
			// 未知帧，跳过
			if payloadLen > 0 { io.CopyN(io.Discard, w.reader, payloadLen) }
			continue
		}
	}
}
