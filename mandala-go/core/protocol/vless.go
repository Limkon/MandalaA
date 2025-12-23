package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

// BuildVlessPayload 构造 VLESS 握手包 (Version 0)
func BuildVlessPayload(uuidStr, targetHost string, targetPort int) ([]byte, error) {
	log.Printf("[Vless] 开始构造请求 -> %s:%d (UUID: %s)", targetHost, targetPort, uuidStr)
	
	uuid, err := ParseUUID(uuidStr) 
	if err != nil {
		log.Printf("[Vless] UUID 解析错误: %v", err)
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
			buf.WriteByte(0x01)
			buf.Write(ip4)
			log.Printf("[Vless] 地址类型: IPv4")
		} else {
			buf.WriteByte(0x03)
			buf.Write(ip.To16())
			log.Printf("[Vless] 地址类型: IPv6")
		}
	} else {
		if len(targetHost) > 255 {
			return nil, fmt.Errorf("domain name too long: %s", targetHost)
		}
		buf.WriteByte(0x02)
		buf.WriteByte(byte(len(targetHost)))
		buf.WriteString(targetHost)
		log.Printf("[Vless] 地址类型: 域名 (%s)", targetHost)
	}

	log.Printf("[Vless] 请求包构造完成")
	return buf.Bytes(), nil
}

// VlessConn 包装器，用于剥离 VLESS 服务端响应头
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

	if vc.reader == nil {
		vc.reader = vc.Conn
	}

	log.Printf("[Vless] 正在读取并剥离服务端响应头...")
	head := make([]byte, 2)
	n, err := io.ReadFull(vc.reader, head)
	if err != nil {
		log.Printf("[Vless] 读取响应头失败: %v", err)
		return n, err
	}

	addonLen := int(head[1])
	if addonLen > 0 {
		log.Printf("[Vless] 发现 Addon 数据，长度: %d，正在丢弃", addonLen)
		discard := make([]byte, addonLen)
		if _, err := io.ReadFull(vc.reader, discard); err != nil {
			return 0, err
		}
	}

	vc.headerStripped = true
	log.Printf("[Vless] 响应头剥离成功，进入数据传输阶段")

	if len(b) == 0 {
		return 0, nil
	}

	return vc.Conn.Read(b)
}
