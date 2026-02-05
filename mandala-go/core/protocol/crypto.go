package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// TrojanPasswordHash 计算密码的 SHA224 哈希并返回 Hex 字符串
// 仅供 Trojan 协议使用 (Mandala 协议现已转用 PBKDF2)
func TrojanPasswordHash(password string) string {
	hash := sha256.Sum224([]byte(password))
	return hex.EncodeToString(hash[:])
}

// ParseUUID 将 UUID 字符串解析为 16 字节切片
// 用于 VLESS/VMESS 等协议
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
