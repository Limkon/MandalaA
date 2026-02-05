package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// TrojanPasswordHash 计算密码的 SHA224 哈希并返回 Hex 字符串
func TrojanPasswordHash(password string) string {
	hash := sha256.Sum224([]byte(password))
	return hex.EncodeToString(hash[:])
}

// ParseUUID 将 UUID 字符串解析为 16 字节切片
func ParseUUID(uuidStr string) ([]byte, error) {
	clean := strings.ReplaceAll(uuidStr, "-", "")
	clean = strings.ReplaceAll(clean, " ", "")
	clean = strings.ReplaceAll(clean, "{", "")
	clean = strings.ReplaceAll(clean, "}", "")
	
	bytes, err := hex.DecodeString(clean)
	if err != nil {
		return nil, err
	}
	if len(bytes) != 16 {
		out := make([]byte, 16)
		copy(out, bytes)
		return out, nil
	}
	return bytes, nil
}

// ==========================================
// [New Feature] Xorshift128+ 流式混淆工具
// ==========================================

type StreamCipher struct {
	s [4]uint32 // 128-bit state
}

// MurmurHash3 fmix32 (用于种子混合)
func fmix32(h uint32) uint32 {
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// NewStreamCipher 初始化流加密状态
// 算法必须严格匹配 JS/C 端：
// 1. 种子生成：s = s * 31 + byte (Go uint32 overflow 自动处理，等效于 C 的无符号溢出和 JS 的 Math.imul)
// 2. 状态混合：fmix32
func NewStreamCipher(key []byte, salt []byte) *StreamCipher {
	s1, s2 := uint32(0), uint32(0)

	// [Critical] 核心种子生成算法，必须与服务端保持一致
	for _, b := range key {
		s1 = s1*31 + uint32(b)
	}
	for _, b := range salt {
		s2 = s2*31 + uint32(b)
	}

	// 增加非线性扰动
	s3 := fmix32(s1 ^ 0x12345678)
	s4 := fmix32(s2 ^ 0x87654321)
	s1 = fmix32(s1)
	s2 = fmix32(s2)

	return &StreamCipher{s: [4]uint32{s1, s2, s3, s4}}
}

// Next 生成下一个 32位随机数 (Xorshift128+)
func (c *StreamCipher) Next() uint32 {
	t := c.s[3]
	s := c.s[0]
	c.s[3] = c.s[2]
	c.s[2] = c.s[1]
	c.s[1] = s
	t ^= t << 11
	t ^= t >> 8
	c.s[0] = t ^ s ^ (s >> 19)
	return c.s[0]
}

// Process 原地处理 Buffer (异或加密/解密)
func (c *StreamCipher) Process(buf []byte) {
	length := len(buf)
	i := 0
	var randomCache uint32
	var cacheRemaining int = 0

	for i < length {
		if cacheRemaining == 0 {
			randomCache = c.Next()
			cacheRemaining = 4
		}

		// 取最低 8 位进行异或 (Little Endian 序处理字节流)
		buf[i] ^= byte(randomCache & 0xFF)
		randomCache >>= 8
		cacheRemaining--
		i++
	}
}
