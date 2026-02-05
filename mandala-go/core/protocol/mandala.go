package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
)

// MandalaClient 处理 Mandala 协议的客户端逻辑
type MandalaClient struct {
	Username string
	Password string
}

// NewMandalaClient 创建一个新的 Mandala 客户端实例
func NewMandalaClient(username, password string) *MandalaClient {
	return &MandalaClient{
		Username: username,
		Password: password,
	}
}

// BuildHandshakePayload 构造 Mandala 协议的握手包
// [Refactor] 2026-02-04: Updated to use AES-256-GCM + PBKDF2 (1000 iter)
// useNoise parameter is ignored in this version as GCM provides semantic security
func (c *MandalaClient) BuildHandshakePayload(targetHost string, targetPort int, useNoise bool) ([]byte, error) {
	// log.Printf("[Mandala] 开始构造握手包 (AES-GCM) -> %s:%d", targetHost, targetPort)

	// 1. Construct Plaintext Payload
	// Format: [CMD(1)] [ATYP(1)] [ADDR(Var)] [PORT(2)]
	var buf bytes.Buffer

	// 1.1 CMD (0x01) - Connect
	buf.WriteByte(0x01)

	// 1.2 Target Address (SOCKS5 style)
	ip := net.ParseIP(targetHost)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf.WriteByte(0x01) // ATYP_IPV4
			buf.Write(ip4)
			// log.Printf("[Mandala] 目标类型: IPv4")
		} else {
			buf.WriteByte(0x04) // ATYP_IPV6
			buf.Write(ip.To16())
			// log.Printf("[Mandala] 目标类型: IPv6")
		}
	} else {
		if len(targetHost) > 255 {
			return nil, errors.New("domain too long")
		}
		buf.WriteByte(0x03) // ATYP_DOMAIN
		buf.WriteByte(byte(len(targetHost)))
		buf.WriteString(targetHost)
		// log.Printf("[Mandala] 目标类型: 域名 (%s)", targetHost)
	}

	// 1.3 Port (2 bytes Big Endian)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(targetPort))
	buf.Write(portBuf)

	// Note: No CRLF in the new protocol design for AES-GCM payload

	// 2. Encrypt Payload using AES-256-GCM
	// The Password (UUID) is used as the key source
	encryptedBytes, err := MandalaPack(c.Password, buf.Bytes())
	if err != nil {
		log.Printf("[Mandala] Encryption failed: %v", err)
		return nil, err
	}

	// log.Printf("[Mandala] 握手包构造完成 (AES-GCM)，总长度: %d", len(encryptedBytes))
	return encryptedBytes, nil
}
