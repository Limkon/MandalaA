package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// 常量定义
const (
	MandalaSalt   = "mandala-protocol-salt-v1"
	MandalaIter   = 1000
	MandalaKeyLen = 32 // 256 bits
	MandalaIVLen  = 12 // GCM IV
	MandalaTagLen = 16 // GCM Tag
)

type MandalaClient struct {
	Username string
	Password string
	key      []byte
}

func NewMandalaClient(username, password string) *MandalaClient {
	// 去除首尾空格，防止输入法误触
	cleanPassword := strings.TrimSpace(password)
	
	c := &MandalaClient{
		Username: username,
		Password: cleanPassword,
	}
	c.deriveKey()
	return c
}

func (c *MandalaClient) deriveKey() {
	if c.Password == "" {
		log.Printf("[Mandala] 错误：密码为空！")
		return
	}

	// [核心修改] 尝试模拟 C 语言 sizeof 的行为
	// 很多 C 代码会错误地使用 sizeof("string")，导致 salt 包含一个看不见的 '\0'
	// Go 默认不包含这个 '\0'。为了兼容，我们手动加上它。
	saltBytes := []byte(MandalaSalt)
	
	// *** 如果这次还是连不上，请尝试注释掉下面这一行 (append) 再试 ***
	// 或者是服务端使用了 sizeof(password) 导致密码也多了 \0 ?
	// 目前先假设是 Salt 的问题，因为 Salt 是硬编码常量，容易用错 sizeof
	// saltBytes = append(saltBytes, 0x00) // 暂不默认开启，先通过打印对比

	// 方案 A: 标准行为 (不加 \0)
	c.key = pbkdf2.Key([]byte(c.Password), saltBytes, MandalaIter, MandalaKeyLen, sha256.New)
	log.Printf("[Mandala] Key (Standard): %s", hex.EncodeToString(c.key))

	// 方案 B: 兼容 C 语言 sizeof 行为 (Salt + \0)
	// 如果标准行为失败，请手动将下面这段代码取消注释，并注释掉上面的 方案 A
	/*
	saltWithNull := append([]byte(MandalaSalt), 0x00)
	c.key = pbkdf2.Key([]byte(c.Password), saltWithNull, MandalaIter, MandalaKeyLen, sha256.New)
	log.Printf("[Mandala] Key (C-Style \0): %s", hex.EncodeToString(c.key))
	*/
}

// BuildHandshakePayload 构造 Mandala 协议的握手包
func (c *MandalaClient) BuildHandshakePayload(targetHost string, targetPort int) ([]byte, error) {
	if len(c.key) == 0 {
		c.deriveKey()
		if len(c.key) == 0 {
			return nil, errors.New("failed to derive key")
		}
	}

	var buf bytes.Buffer

	// 1. CMD (0x01)
	buf.WriteByte(0x01)

	// 2. Address & Port
	// 严格按照 [ATYP] [ADDR] [PORT] 顺序
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

	// 3. Port (Big Endian)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(targetPort))
	buf.Write(portBuf)

	plaintext := buf.Bytes()
	
	// [Debug] 打印明文，确保没有混入奇怪的字节
	// log.Printf("[Mandala] Plaintext: %s", hex.EncodeToString(plaintext))

	return c.mandalaPack(plaintext)
}

func (c *MandalaClient) mandalaPack(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, MandalaIVLen)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Seal: IV + Cipher + Tag
	ciphertext := aesgcm.Seal(iv, iv, plaintext, nil)
	return ciphertext, nil
}
