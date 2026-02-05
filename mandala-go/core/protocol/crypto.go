package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"sync"

	"golang.org/x/crypto/pbkdf2"
)

// Constants for Mandala Protocol
const (
	MandalaSalt       = "mandala-protocol-salt-v1"
	MandalaIterations = 1000
	MandalaKeyLen     = 32 // AES-256
	MandalaIVLen      = 12 // GCM Standard IV
)

var (
	// Global cache for PBKDF2 derived keys to avoid re-computation
	mandalaKeyCache sync.Map
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
// [Final Fix] PBKDF2 + Safe Memory Allocation
// ==========================================

// MandalaDeriveKey derives the AES-GCM key from the password using PBKDF2
func MandalaDeriveKey(password string) []byte {
	// 1. Check cache
	if key, ok := mandalaKeyCache.Load(password); ok {
		return key.([]byte)
	}

	// 2. Compute key (PBKDF2 SHA256 1000 Iterations) - Must match Server
	key := pbkdf2.Key([]byte(password), []byte(MandalaSalt), MandalaIterations, MandalaKeyLen, sha256.New)

	// 3. Store in cache
	mandalaKeyCache.Store(password, key)
	return key
}

// MandalaPack encrypts the plaintext using AES-256-GCM
// Output format: [IV (12 bytes)] + [Ciphertext + Tag (16 bytes)]
func MandalaPack(password string, plaintext []byte) ([]byte, error) {
	key := MandalaDeriveKey(password)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// [Safety] 1. Generate IV independently
	iv := make([]byte, MandalaIVLen)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// [Safety] 2. Encrypt to a separate buffer first (auto-appends Tag)
	// Seal(dst, nonce, plaintext, data) -> appends result to dst
	// passing nil as dst creates a new slice
	encryptedData := aesgcm.Seal(nil, iv, plaintext, nil)

	// [Safety] 3. Combine [IV] + [Cipher+Tag]
	// Explicit concatenation avoids any slice capacity confusion
	finalMsg := make([]byte, 0, len(iv)+len(encryptedData))
	finalMsg = append(finalMsg, iv...)
	finalMsg = append(finalMsg, encryptedData...)

	return finalMsg, nil
}
