package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// BuildVlessPayload 构造 VLESS 握手包
// 修复：使用 VLESS 特定的地址类型常量 (IPv4=1, Domain=2, IPv6=3)
func BuildVlessPayload(uuidStr, targetHost string, targetPort int) ([]byte, error) {
	uuid, err := ParseUUID(uuidStr)
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

	// 写入地址 (VLESS 格式)
	ip := net.ParseIP(targetHost)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4: 0x01 + 4 bytes
			buf.WriteByte(0x01)
			buf.Write(ip4)
		} else {
			// IPv6: 0x03 + 16 bytes (注意：SOCKS5是0x04，VLESS是0x03)
			buf.WriteByte(0x03)
			buf.Write(ip.To16())
		}
	} else {
		// Domain: 0x02 + Len + Domain (注意：SOCKS5是0x03，VLESS是0x02)
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

	// 第一次读取，需要剥离头部
	// 我们不能假设头部和数据在同一个包里，也不能假设分包
	// 但通常 VLESS 响应头很小 (Version=0, AddonLen=0 -> 2 bytes)
	
	// 为了简单起见，我们读取并检查 Version 和 AddonLen
	// 注意：这里假设底层的 Conn (如 WSConn) 已经处理了帧边界，
	// 或者 TCP 流式读取。
	
	if vc.reader == nil {
		vc.reader = vc.Conn
	}

	// 读取前两个字节 [Version, AddonLen]
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
	
	// 此时 header 已剥离，尝试读取剩余数据到用户 buffer
	// 如果用户 buffer 长度为 0，直接返回
	if len(b) == 0 {
		return 0, nil
	}
	
	return vc.Conn.Read(b)
}
