package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
)

// BuildShadowsocksPayload 构造 Shadowsocks 握手包 (Socks5 格式地址)
func BuildShadowsocksPayload(targetHost string, targetPort int) ([]byte, error) {
	var buf bytes.Buffer

	ip := net.ParseIP(targetHost)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf.WriteByte(0x01)
			buf.Write(ip4)
		} else {
			buf.WriteByte(0x04)
			buf.Write(ip.To16())
		}
	} else {
		if len(targetHost) > 255 {
			return nil, errors.New("domain too long")
		}
		buf.WriteByte(0x03)
		buf.WriteByte(byte(len(targetHost)))
		buf.WriteString(targetHost)
	}

	if targetPort < 0 || targetPort > 65535 {
		return nil, errors.New("invalid port: " + strconv.Itoa(targetPort))
	}
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(targetPort))
	buf.Write(portBuf)

	return buf.Bytes(), nil
}
