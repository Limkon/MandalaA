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

// BuildHandshakePayload 构造 Mandala 协议的握手包
// [Refactor] 使用 Xorshift128+ 替代简单的 Salt XOR
func (c *MandalaClient) BuildHandshakePayload(targetHost string, targetPort int, useNoise bool) ([]byte, error) {
	log.Printf("[Mandala] 开始构造握手包 -> %s:%d", targetHost, targetPort)

	// 1. 生成随机 Salt (4 bytes)
	salt := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	// log.Printf("[Mandala] 生成随机 Salt: %x", salt)

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
	var padLen int
	if useNoise {
		b := make([]byte, 1)
		rand.Read(b)
		padLen = 32 + int(b[0]%128)
	} else {
		b := make([]byte, 1)
		rand.Read(b)
		padLen = int(b[0] % 16)
	}

	buf.WriteByte(byte(padLen))

	if padLen > 0 {
		padding := make([]byte, padLen)
		if _, err := io.ReadFull(rand.Reader, padding); err != nil {
			return nil, err
		}
		buf.Write(padding)
	}
	// log.Printf("[Mandala] Padding: %d", padLen)

	// 2.3 指令 CMD (0x01 Connect)
	buf.WriteByte(0x01)

	// 2.4 目标地址
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

	// 2.5 端口
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(targetPort))
	buf.Write(portBuf)

	// 2.6 CRLF
	buf.Write([]byte{0x0D, 0x0A})

	// 3. 构造最终包 (Salt + Xorshift128+ Encrypted Payload)
	plaintext := buf.Bytes()
	finalSize := 4 + len(plaintext)
	finalBuf := make([]byte, finalSize)

	// 写入头部 Salt
	copy(finalBuf[0:4], salt)
	
	// 写入明文到缓冲区
	copy(finalBuf[4:], plaintext)
	
	// 初始化流加密 (Key=Password, Salt=Salt)
	// [Critical] 使用与服务端一致的加密算法
	cipher := NewStreamCipher([]byte(c.Password), salt)
	
	// 对 Buffer 的数据部分（跳过 Salt）进行原地加密
	cipher.Process(finalBuf[4:])

	log.Printf("[Mandala] 握手包构造完成 (Xorshift128+)，总长度: %d", finalSize)
	return finalBuf, nil
}
