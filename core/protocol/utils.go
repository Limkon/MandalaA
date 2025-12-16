package protocol

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

// ToSocksAddr 将 host:port 转换为 SOCKS5 地址格式的字节切片
// 格式: [Type][Addr...][PortHigh][PortLow]
// Type: 0x01(IPv4), 0x03(Domain), 0x04(IPv6)
func ToSocksAddr(host string, port int) ([]byte, error) {
	var buf []byte

	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4: [0x01][4 bytes IP][2 bytes Port]
			buf = make([]byte, 1+4+2)
			buf[0] = 0x01
			copy(buf[1:], ip4)
		} else {
			// IPv6: [0x04][16 bytes IP][2 bytes Port]
			buf = make([]byte, 1+16+2)
			buf[0] = 0x04
			copy(buf[1:], ip.To16())
		}
	} else {
		// Domain: [0x03][Len][Domain...][2 bytes Port]
		if len(host) > 255 {
			return nil, fmt.Errorf("domain name too long: %s", host)
		}
		buf = make([]byte, 1+1+len(host)+2)
		buf[0] = 0x03
		buf[1] = byte(len(host))
		copy(buf[2:], host)
	}

	// 写入端口 (Big Endian)
	binary.BigEndian.PutUint16(buf[len(buf)-2:], uint16(port))

	return buf, nil
}

// SplitHostPort 分离 host 和 port，处理可能的错误
func SplitHostPort(address string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}
