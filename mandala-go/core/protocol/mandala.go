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
// [Update] V2: 引入完整性校验 (Integrity Check)
// 结构: [Salt(4)] [StreamXOR( SHA256(AuthKey+Header) + Header )]
func (c *MandalaClient) BuildHandshakePayload(targetHost string, targetPort int, useNoise bool) ([]byte, error) {
	log.Printf("[Mandala] 开始构造 V2 握手包 -> %s:%d", targetHost, targetPort)

	// 1. 生成随机 Salt (4 bytes)
	salt := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	// 2. 准备 AuthKey (SHA224 Hex String, 56 bytes)
	// 这是用于计算签名的密钥，与服务端缓存的密钥一致
	hash224 := sha256.Sum224([]byte(c.Password))
	authKey := make([]byte, hex.EncodedLen(len(hash224)))
	hex.Encode(authKey, hash224[:])

	// 3. 构建 Header 部分 (暂存到 buffer)
	// Header: [PadLen] [Padding] [CMD] [ATYP] [Addr] [Port] [CRLF]
	var headerBuf bytes.Buffer

	// 3.1 随机填充 (Padding)
	b := make([]byte, 1)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}

	var padLen int
	if useNoise {
		// 启用噪音模式：填充 32 ~ 95 字节 (限制最大长度防止包过大)
		padLen = 32 + int(b[0]%64)
	} else {
		// 标准模式：填充 0 ~ 63 字节
		padLen = int(b[0] % 64)
	}

	headerBuf.WriteByte(byte(padLen)) // 写入填充长度字节

	if padLen > 0 {
		padding := make([]byte, padLen)
		if _, err := io.ReadFull(rand.Reader, padding); err != nil {
			return nil, err
		}
		headerBuf.Write(padding)
	}

	// 3.2 指令 CMD (0x01 Connect)
	// 目前仅支持 TCP Connect，UDP 需要根据需求传入参数修改
	headerBuf.WriteByte(0x01)

	// 3.3 目标地址 (SOCKS5 格式)
	ip := net.ParseIP(targetHost)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			headerBuf.WriteByte(0x01) // IPv4
			headerBuf.Write(ip4)
		} else {
			headerBuf.WriteByte(0x04) // IPv6
			headerBuf.Write(ip.To16())
		}
	} else {
		if len(targetHost) > 255 {
			return nil, errors.New("domain too long")
		}
		headerBuf.WriteByte(0x03) // Domain
		headerBuf.WriteByte(byte(len(targetHost)))
		headerBuf.WriteString(targetHost)
	}

	// 3.4 端口 (2 bytes Big Endian)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(targetPort))
	headerBuf.Write(portBuf)

	// 3.5 CRLF (0x0D 0x0A)
	headerBuf.Write([]byte{0x0D, 0x0A})

	headerBytes := headerBuf.Bytes()

	// 4. 计算完整性校验哈希 (Integrity Hash)
	// Signature = SHA256( AuthKey + Header )
	verifyBuf := make([]byte, len(authKey)+len(headerBytes))
	copy(verifyBuf[0:], authKey)
	copy(verifyBuf[len(authKey):], headerBytes)

	signature := sha256.Sum256(verifyBuf) // 32 bytes

	// 5. 构造明文 Payload
	// [Signature(32)] + [Header]
	plaintextLen := 32 + len(headerBytes)
	plaintext := make([]byte, plaintextLen)
	copy(plaintext[0:], signature[:])
	copy(plaintext[32:], headerBytes)

	// 6. 构造最终包 (Salt + Encrypted Payload)
	finalSize := 4 + plaintextLen
	finalBuf := make([]byte, finalSize)

	// 6.1 写入头部 Salt
	copy(finalBuf[0:4], salt)

	// 6.2 写入明文到缓冲区 (从第4字节开始)
	copy(finalBuf[4:], plaintext)

	// 6.3 初始化流加密 (Key=Password, Salt=Salt)
	cipher := NewStreamCipher([]byte(c.Password), salt)

	// 6.4 对 Buffer 的数据部分（跳过 Salt）进行原地加密
	cipher.Process(finalBuf[4:])

	// log.Printf("[Mandala] V2 握手包构造完成，总长度: %d", finalSize)
	return finalBuf, nil
}
