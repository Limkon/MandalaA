package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"

	"golang.org/x/crypto/pbkdf2"
)

// Constants matches C implementation (MandalaECH)
const (
	MandalaSalt   = "mandala-protocol-salt-v1"
	MandalaIter   = 1000
	MandalaKeyLen = 32 // 256 bits
	MandalaIVLen  = 12 // GCM IV
	MandalaTagLen = 16 // GCM Tag
)

// MandalaClient 处理 Mandala 协议的客户端逻辑
type MandalaClient struct {
	Username string
	Password string
	key      []byte
}

// NewMandalaClient 创建一个新的 Mandala 客户端实例
func NewMandalaClient(username, password string) *MandalaClient {
	c := &MandalaClient{
		Username: username,
		Password: password,
	}
	c.deriveKey()
	return c
}

// deriveKey 使用 PBKDF2 派生密钥
func (c *MandalaClient) deriveKey() {
	if c.Password == "" {
		return
	}
	// PBKDF2-HMAC-SHA256
	c.key = pbkdf2.Key([]byte(c.Password), []byte(MandalaSalt), MandalaIter, MandalaKeyLen, sha256.New)
}

// BuildHandshakePayload 构造 Mandala 协议的握手包
// [Fix] 移除了 Noise 参数，且移除了会导致粘包问题的 CRLF
func (c *MandalaClient) BuildHandshakePayload(targetHost string, targetPort int) ([]byte, error) {
	log.Printf("[Mandala] 开始构造握手包 -> %s:%d", targetHost, targetPort)

	if len(c.key) == 0 {
		c.deriveKey()
		if len(c.key) == 0 {
			return nil, errors.New("failed to derive key")
		}
	}

	// 1. 准备明文 Payload
	var buf bytes.Buffer

	// 1.1 指令 CMD (0x01 Connect)
	buf.WriteByte(0x01)

	// 1.2 目标地址 (SOCKS5 格式)
	ip := net.ParseIP(targetHost)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf.WriteByte(0x01) // IPv4
			buf.Write(ip4)
		} else {
			buf.WriteByte(0x04) // IPv6
			buf.Write(ip.To16())
		}
	} else {
		if len(targetHost) > 255 {
			return nil, errors.New("domain too long")
		}
		buf.WriteByte(0x03) // Domain
		buf.WriteByte(byte(len(targetHost)))
		buf.WriteString(targetHost)
	}

	// 1.3 端口 (2 bytes Big Endian)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(targetPort))
	buf.Write(portBuf)

	// [CRITICAL FIX] 移除 CRLF
	// 旧代码: buf.Write([]byte{0x0D, 0x0A}) 
	// 原因: AES-GCM 协议是紧凑二进制流，多余的 CRLF 会被服务端解密后误判为后续数据包的 Length Header，导致死锁。

	plaintext := buf.Bytes()

	// 2. 加密打包 (AES-GCM)
	return c.mandalaPack(plaintext)
}

// mandalaPack 执行 AES-256-GCM 加密
func (c *MandalaClient) mandalaPack(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 生成随机 IV (12 bytes)
	iv := make([]byte, MandalaIVLen)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// 加密: IV + Ciphertext + Tag
	ciphertext := aesgcm.Seal(iv, iv, plaintext, nil)

	// 此时 IPv4 的总长度应为: 12(IV) + 1+1+4+2(Plain) + 16(Tag) = 36 bytes (之前是 38)
	log.Printf("[Mandala] 握手包构造完成 (AES-256-GCM), 总长度: %d", len(ciphertext))
	return ciphertext, nil
}
