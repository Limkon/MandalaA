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
// 必须与 C 端 src/crypto_mandala.c 保持严格一致
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
	key      []byte // 缓存派生的密钥，避免重复计算
}

// NewMandalaClient 创建一个新的 Mandala 客户端实例
func NewMandalaClient(username, password string) *MandalaClient {
	c := &MandalaClient{
		Username: username,
		Password: password,
	}
	c.deriveKey() // 初始化时预先派生密钥
	return c
}

// deriveKey 使用 PBKDF2 派生密钥
// 对应 C 端: mandala_derive_key
func (c *MandalaClient) deriveKey() {
	if c.Password == "" {
		return
	}
	// PBKDF2-HMAC-SHA256
	// 依赖: golang.org/x/crypto/pbkdf2
	c.key = pbkdf2.Key([]byte(c.Password), []byte(MandalaSalt), MandalaIter, MandalaKeyLen, sha256.New)
}

// BuildHandshakePayload 构造 Mandala 协议的握手包
// 根据 MandalaECH (C语言版) 重构：使用 PBKDF2 + AES-256-GCM
// [Change] 移除了废弃的 useNoise 参数，因为 GCM 模式不再使用随机长度填充
func (c *MandalaClient) BuildHandshakePayload(targetHost string, targetPort int) ([]byte, error) {
	log.Printf("[Mandala] 开始构造握手包 -> %s:%d", targetHost, targetPort)

	// 确保密钥已派生
	if len(c.key) == 0 {
		c.deriveKey()
		if len(c.key) == 0 {
			return nil, errors.New("failed to derive key")
		}
	}

	// 1. 准备明文 Payload
	// 对应 C 端 crypto.h 注释: plaintext: 明文数据 (Command + Address + Port)
	var buf bytes.Buffer

	// 1.1 指令 CMD (0x01 Connect)
	buf.WriteByte(0x01)

	// 1.2 目标地址 (SOCKS5 格式)
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

	// 1.3 端口 (2 bytes Big Endian)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(targetPort))
	buf.Write(portBuf)

	// 1.4 CRLF (0x0D 0x0A)
	buf.Write([]byte{0x0D, 0x0A})

	plaintext := buf.Bytes()

	// 2. 加密打包 (调用 AES-GCM)
	// Output: [IV (12)] + [Ciphertext + Tag (16)]
	return c.mandalaPack(plaintext)
}

// mandalaPack 执行 AES-256-GCM 加密
// 对应 C 端: mandala_pack
func (c *MandalaClient) mandalaPack(plaintext []byte) ([]byte, error) {
	// 1. 创建 AES Cipher
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	// 2. 创建 GCM 模式
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 3. 生成随机 IV (12 bytes)
	iv := make([]byte, MandalaIVLen)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// 4. 加密 (Seal)
	// Seal(dst, nonce, plaintext, additionalData)
	// 结果格式: iv + ciphertext + tag
	ciphertext := aesgcm.Seal(iv, iv, plaintext, nil)

	log.Printf("[Mandala] 握手包构造完成 (AES-256-GCM), 总长度: %d", len(ciphertext))
	return ciphertext, nil
}
