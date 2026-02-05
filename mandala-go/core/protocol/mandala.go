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

type MandalaClient struct {
	Username string
	Password string
	key      []byte
}

func NewMandalaClient(username, password string) *MandalaClient {
	c := &MandalaClient{
		Username: username,
		Password: password,
	}
	c.deriveKey()
	return c
}

func (c *MandalaClient) deriveKey() {
	if c.Password == "" {
		log.Printf("[Mandala] 警告：密码为空！")
		return
	}
	// 严格对齐 C: PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, sha256, keylen, out)
	c.key = pbkdf2.Key([]byte(c.Password), []byte(MandalaSalt), MandalaIter, MandalaKeyLen, sha256.New)
	
	// [Debug] 打印密钥指纹，用于检查是否与服务端一致
	log.Printf("[Mandala] Key Derived (Hex): %s", hex.EncodeToString(c.key))
}

// BuildHandshakePayload 构造 Mandala 协议的握手包
func (c *MandalaClient) BuildHandshakePayload(targetHost string, targetPort int) ([]byte, error) {
	if len(c.key) == 0 {
		c.deriveKey()
		if len(c.key) == 0 {
			return nil, errors.New("failed to derive key")
		}
	}

	// 1. 准备明文 Payload
	// 对应 C 代码: payload[p_len++] = ...
	var buf bytes.Buffer

	// 1.1 CMD (0x01)
	buf.WriteByte(0x01)

	// 1.2 Address & Port
	// C代码逻辑：先尝试 IPv4，再 IPv6，最后域名
	ip := net.ParseIP(targetHost)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4: [0x01] + [4 bytes IP]
			buf.WriteByte(0x01) 
			buf.Write(ip4)
		} else {
			// IPv6: [0x04] + [16 bytes IP]
			buf.WriteByte(0x04)
			buf.Write(ip.To16())
		}
	} else {
		// Domain: [0x03] + [1 byte Len] + [Domain String]
		if len(targetHost) > 255 {
			return nil, errors.New("domain too long")
		}
		buf.WriteByte(0x03)
		buf.WriteByte(byte(len(targetHost)))
		buf.WriteString(targetHost)
	}

	// 1.3 Port (Big Endian)
	// C: unsigned short port_be = htons((unsigned short)s->config.port);
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(targetPort))
	buf.Write(portBuf)

	plaintext := buf.Bytes()
	log.Printf("[Mandala] Plaintext (Hex): %s", hex.EncodeToString(plaintext))

	// 2. 加密打包 (AES-GCM)
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

	// 生成随机 IV (12 bytes)
	iv := make([]byte, MandalaIVLen)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// 加密: Seal(dst, nonce, plaintext, additionalData)
	// Seal 会将密文和 Tag 追加到 dst (这里是 iv) 后面
	// 结果结构: [IV] + [Ciphertext] + [Tag]
	// 这完全符合 C 代码: memcpy(iv)... EVP_EncryptUpdate... EVP_CIPHER_CTX_ctrl(TAG)
	ciphertext := aesgcm.Seal(iv, iv, plaintext, nil)

	log.Printf("[Mandala] Final Packet (Len: %d): %s", len(ciphertext), hex.EncodeToString(ciphertext))
	return ciphertext, nil
}
