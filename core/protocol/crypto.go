package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// TrojanPasswordHash 计算密码的 SHA224 哈希并返回 Hex 字符串
// 对应原项目 crypto.c 中的 trojan_password_hash 函数
// Mandala 协议使用这个生成的 56 字节 Hex 字符串作为认证凭证
func TrojanPasswordHash(password string) string {
	hash := sha256.Sum224([]byte(password))
	return hex.EncodeToString(hash[:])
}

// ParseUUID 将 UUID 字符串解析为 16 字节切片
// 对应原项目 proxy.c 中的 parse_uuid 函数
// 支持带横杠或不带横杠的格式
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
		// 如果长度不足或过长，简单截断或补零处理，或者返回错误
		// 这里为了稳定性，如果不足则补零，超过截断（模拟 C 行为）
		out := make([]byte, 16)
		copy(out, bytes)
		return out, nil
	}
	return bytes, nil
}
