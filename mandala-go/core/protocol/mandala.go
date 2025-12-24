package protocol

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
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

// [修改] BuildHandshakePayload 构造 Mandala 协议的握手包
// 增加 noiseSize 参数：控制随机填充的最大长度
func (c *MandalaClient) BuildHandshakePayload(targetHost string, targetPort int, noiseSize int) ([]byte, error) {
	log.Printf("[Mandala] 开始构造握手包 -> %s:%d (最大填充: %d)", targetHost, targetPort, noiseSize)

	// 1. 生成随机 Salt (4 bytes)
	salt := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	// 2. 准备明文 Payload
	var buf bytes.Buffer

	// 2.1 哈希 ID (SHA224 Hex String, 56 bytes)
	hash := sha256.Sum224([]byte(c.Password))
	hashHex := hex.EncodeToString(hash[:])
	if len(hashHex) != 56 {
		return nil, errors.New("hash generation failed")
	}
	buf.WriteString(hashHex)

	// 2.2 随机填充 (Padding)
	padLen := 0
	if noiseSize > 0 {
		// 生成 0 到 noiseSize 之间的随机长度
		// 读取 2 字节随机数用于取模
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(rand.Reader, lenBuf); err == nil {
			val := int(binary.BigEndian.Uint16(lenBuf))
			padLen = val % (noiseSize + 1)
		}
	}

	// 写入填充长度 (1 byte)
	buf.WriteByte(byte(padLen))

	// 写入填充内容
	if padLen > 0 {
		padding := make([]byte, padLen)
		if _, err := io.ReadFull(rand.Reader, padding); err != nil {
			return nil, err
		}
		buf.Write(padding)
	}

	// 2.3 指令 CMD (0x01 Connect)
	buf.WriteByte(0x01)

	// 2.4 目标地址 (SOCKS5 格式)
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

	// 2.5 端口 (2 bytes Big Endian)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(targetPort))
	buf.Write(portBuf)

	// 2.6 CRLF (0x0D 0x0A)
	buf.Write([]byte{0x0D, 0x0A})

	// 3. 构造最终包 (Salt + XOR Encrypted Payload)
	plaintext := buf.Bytes()
	finalSize := 4 + len(plaintext)
	finalBuf := make([]byte, finalSize)

	copy(finalBuf[0:4], salt)

	// 执行 XOR 加密
	for i := 0; i < len(plaintext); i++ {
		finalBuf[4+i] = plaintext[i] ^ salt[i%4]
	}

	log.Printf("[Mandala] 握手包构造完成，总长度: %d", finalSize)
	return finalBuf, nil
}
