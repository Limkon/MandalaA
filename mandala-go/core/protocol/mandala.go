package protocol

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
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
// 协议结构参考:
// Salt(4) + XOR( Hash(56) + PadLen(1) + Padding(N) + Cmd(1) + AddrType(1) + Addr... + Port(2) + CRLF(2) )
func (c *MandalaClient) BuildHandshakePayload(targetHost string, targetPort int) ([]byte, error) {
	// 1. 生成随机 Salt (4 bytes)
	salt := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	// 2. 准备明文 Payload (临时缓冲区)
	var buf bytes.Buffer

	// 2.1 哈希 ID (SHA224 Hex String, 56 bytes)
	// 对应 C 代码: trojan_password_hash(g_proxyConfig.pass, hex_pass);
	// 使用密码生成 SHA224 哈希并转为 Hex 字符串
	hash := sha256.Sum224([]byte(c.Password))
	hashHex := hex.EncodeToString(hash[:]) // 28 bytes binary -> 56 bytes hex string
	if len(hashHex) != 56 {
		return nil, errors.New("hash generation failed")
	}
	buf.WriteString(hashHex)

	// 2.2 随机填充 (Padding)
	// 对应 C 代码: int pad_len = rand() % 16;
	padLenByte := make([]byte, 1)
	if _, err := io.ReadFull(rand.Reader, padLenByte); err != nil {
		return nil, err
	}
	padLen := int(padLenByte[0] % 16)

	buf.WriteByte(byte(padLen)) // PadLen (1 byte)

	if padLen > 0 {
		padding := make([]byte, padLen)
		if _, err := io.ReadFull(rand.Reader, padding); err != nil {
			return nil, err
		}
		buf.Write(padding) // Padding (N bytes)
	}

	// 2.3 指令 CMD (0x01 Connect)
	buf.WriteByte(0x01)

	// 2.4 目标地址 (SOCKS5 格式)
	ip := net.ParseIP(targetHost)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4: 0x01 + 4 bytes IP
			buf.WriteByte(0x01)
			buf.Write(ip4)
		} else {
			// IPv6: 0x04 + 16 bytes IP
			buf.WriteByte(0x04)
			buf.Write(ip.To16())
		}
	} else {
		// Domain: 0x03 + Len(1) + DomainString
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

	// 写入 Salt 到头部
	copy(finalBuf[0:4], salt)

	// 执行 XOR 加密: Cipher[i] = Plain[i] ^ Salt[i % 4]
	for i := 0; i < len(plaintext); i++ {
		finalBuf[4+i] = plaintext[i] ^ salt[i%4]
	}

	return finalBuf, nil
}
