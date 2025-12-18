package protocol

import (
	"bytes"
)

// BuildTrojanPayload 构造标准 Trojan 握手包
// 结构: Hash(pass) + CRLF + CMD(1) + SOCKS5_ADDR + CRLF
func BuildTrojanPayload(password, targetHost string, targetPort int) ([]byte, error) {
	var buf bytes.Buffer

	// 1. 密码哈希 (使用 crypto.go 中的 TrojanPasswordHash)
	buf.WriteString(TrojanPasswordHash(password))
	buf.Write([]byte{0x0D, 0x0A}) // CRLF

	// 2. 指令 (0x01 Connect)
	buf.WriteByte(0x01)

	// 3. 目标地址 (调用 utils.go 中的 ToSocksAddr)
	addr, err := ToSocksAddr(targetHost, targetPort)
	if err != nil {
		return nil, err
	}
	buf.Write(addr)

	// 4. CRLF 结尾
	buf.Write([]byte{0x0D, 0x0A})

	return buf.Bytes(), nil
}
