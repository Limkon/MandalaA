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
	conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	// 如果启用分片且不是 WS 模式，包装连接以拆分第一个 TLS 包
	if d.Config.Settings != nil && d.Config.Settings.TlsFragment && (d.Config.Transport == nil || d.Config.Transport.Type != "ws") {
		size := d.Config.Settings.FragmentSize
		if size <= 0 {
			size = 5
		}
		conn = NewFragmentConn(conn, size)
	}

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
			return nil, fmt.Errorf("tls 握手失败: %v", err)
		}
		conn = tlsConn
	}

	if d.Config.Transport != nil && d.Config.Transport.Type == "ws" {
		wsConn, err := d.handshakeWebSocket(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("websocket 握手失败: %v", err)
		}
		return wsConn, nil
	}

	return conn, nil
}

func (d *Dialer) handshakeWebSocket(conn net.Conn) (net.Conn, error) {
	path := d.Config.Transport.Path
	if path == "" { path = "/" }
	
	// 修复：增加判空检查，防止 Config.TLS 为 nil 时崩溃
	host := d.Config.Server
	if d.Config.TLS != nil && d.Config.TLS.ServerName != "" {
		host = d.Config.TLS.ServerName
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
		return nil, fmt.Errorf("非预期的状态码: %d", resp.StatusCode)
	}

	return NewWSConn(conn, br), nil
}

type FragmentConn struct {
	net.Conn
	fragmentSize  int
	wasFragmented bool
}

func NewFragmentConn(c net.Conn, size int) *FragmentConn {
	return &FragmentConn{Conn: c, fragmentSize: size}
}

func (f *FragmentConn) Write(b []byte) (int, error) {
	if f.wasFragmented || len(b) <= f.fragmentSize {
		return f.Conn.Write(b)
	}
	f.wasFragmented = true
	n, err := f.Conn.Write(b[:f.fragmentSize])
	if err != nil {
		return n, err
	}
	time.Sleep(1 * time.Millisecond)
	m, err := f.Conn.Write(b[f.fragmentSize:])
	return n + m, err
}

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
	buf := make([]byte, 0, 14+length)
	buf = append(buf, 0x82) 
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
		if w.remaining > 0 {
			limit := int64(len(b))
			if w.remaining < limit { limit = w.remaining }
			n, err := w.reader.Read(b[:limit])
			if n > 0 { w.remaining -= int64(n) }
			if n > 0 || err != nil { return n, err }
		}
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
		if masked {
			if _, err := io.CopyN(io.Discard, w.reader, 4); err != nil { return 0, err }
		}
		switch opcode {
		case 0x8: return 0, io.EOF
		case 0x9, 0xA:
			if payloadLen > 0 { io.CopyN(io.Discard, w.reader, payloadLen) }
			continue
		case 0x0, 0x1, 0x2:
			w.remaining = payloadLen
			if w.remaining == 0 { continue }
		default:
			if payloadLen > 0 { io.CopyN(io.Discard, w.reader, payloadLen) }
			continue
		}
	}
}
