package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// BuildVlessPayload 构造 VLESS 握手包 (Version 0)
// 结构: Version(1) + UUID(16) + AddonLen(1) + CMD(1) + PORT(2) + ATYP(1) + ADDR
// 修复：使用 VLESS 特定的地址类型常量 (IPv4=1, Domain=2, IPv6=3)
func BuildVlessPayload(uuidStr, targetHost string, targetPort int) ([]byte, error) {
	uuid, err := ParseUUID(uuidStr) // 调用 crypto.go 中的 ParseUUID
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.WriteByte(0x00) // Version 0
	buf.Write(uuid)     // UUID (16 bytes)
	buf.WriteByte(0x00) // Addon Length (0)

	buf.WriteByte(0x01) // Command (Connect TCP)

	// 写入端口 (Big Endian)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(targetPort))
	buf.Write(portBuf)

	// 写入地址 (VLESS 格式: 0x01=IPv4, 0x02=Domain, 0x03=IPv6)
	ip := net.ParseIP(targetHost)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4: 0x01 + 4 bytes IP
			buf.WriteByte(0x01)
			buf.Write(ip4)
		} else {
			// IPv6: 0x03 + 16 bytes IP
			buf.WriteByte(0x03)
			buf.Write(ip.To16())
		}
	} else {
		// Domain: 0x02 + Len(1) + DomainString
		if len(targetHost) > 255 {
			return nil, fmt.Errorf("domain name too long: %s", targetHost)
		}
		buf.WriteByte(0x02)
		buf.WriteByte(byte(len(targetHost)))
		buf.WriteString(targetHost)
	}

	return buf.Bytes(), nil
}

// VlessConn 包装器，用于剥离 VLESS 服务端响应头
// Response Header: [Version(1)][AddonLen(1)][AddonBytes(AddonLen)]
type VlessConn struct {
	net.Conn
	headerStripped bool
	reader         io.Reader
}

func NewVlessConn(c net.Conn) *VlessConn {
	return &VlessConn{Conn: c, headerStripped: false}
}

func (vc *VlessConn) Read(b []byte) (int, error) {
	if vc.headerStripped {
		return vc.Conn.Read(b)
	}

	// 初始化 reader
	if vc.reader == nil {
		vc.reader = vc.Conn
	}

	// 读取前两个字节 [Version, AddonLen]
	// 即使底层是 TCP 流，这里也会阻塞直到读够2字节
	head := make([]byte, 2)
	n, err := io.ReadFull(vc.reader, head)
	if err != nil {
		return n, err
	}

	addonLen := int(head[1])
	if addonLen > 0 {
		// 丢弃 Addon 数据
		discard := make([]byte, addonLen)
		if _, err := io.ReadFull(vc.reader, discard); err != nil {
			return 0, err
		}
	}

	vc.headerStripped = true

	// 此时 header 已剥离，如果调用方提供的 buffer 长度 > 0，则尝试读取真实数据
	if len(b) == 0 {
		return 0, nil
	}

	return vc.Conn.Read(b)
}
