package protocol

import (
	"net"
	"strings"
)

// NewProtocolConn 根据协议类型返回一个已处理握手响应的连接
func NewProtocolConn(conn net.Conn, protocolType string) net.Conn {
	switch strings.ToLower(protocolType) {
	case "vless":
		return NewVlessConn(conn)
	case "shadowsocks":
		// 丢弃可能的预响应
		go func() {
			buf := make([]byte, 1024)
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			conn.Read(buf)
			conn.SetReadDeadline(time.Time{})
		}()
		return conn
	default:
		// SOCKS5、Trojan、Mandala 等已处理或无响应
		return conn
	}
}
