package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// TrojanPasswordHash 计算密码的 SHA224 哈希并返回 Hex 字符串
// 仅供 Trojan 协议使用
func TrojanPasswordHash(password string) string {
	hash := sha256.Sum224([]byte(password))
	return hex.EncodeToString(hash[:])
}

// ParseUUID 将 UUID 字符串解析为 16 字节切片
// 兼容带横杠、空格、大括号等多种格式
func ParseUUID(uuidStr string) ([]byte, error) {
	clean := strings.ReplaceAll(uuidStr, "-", "")
	clean = strings.ReplaceAll(clean, " ", "")
	clean = strings.ReplaceAll(clean, "{", "")
	clean = strings.ReplaceAll(clean, "}", "")
	
	bytes, err := hex.DecodeString(clean)
	if err != nil {
		return nil, err
	}
	
	// 如果解析出的字节数不足16字节，进行补齐（虽然标准UUID应该是16字节）
	if len(bytes) != 16 {
		out := make([]byte, 16)
		copy(out, bytes)
		return out, nil
	}
	return bytes, nil
}
