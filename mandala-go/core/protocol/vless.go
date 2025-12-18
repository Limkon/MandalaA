package protocol

import (
	"bytes"
	"encoding/binary"
)

// BuildVlessPayload 構造簡易 VLESS 握手包 (Version 0)
// 結構: Version(1) + UUID(16) + AddonLen(1) + CMD(1) + PORT(2) + ATYP(1) + ADDR
func BuildVlessPayload(uuidStr, targetHost string, targetPort int) ([]byte, error) {
	uuid, err := ParseUUID(uuidStr) // 調用 crypto.go
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.WriteByte(0x00) // Version 0
	buf.Write(uuid)    // UUID (16 bytes)
	buf.WriteByte(0x00) // Addon Length (目前為 0)

	buf.WriteByte(0x01) // Command (Connect)

	// 寫入端口 (Big Endian)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(targetPort))
	buf.Write(portBuf)

	// 寫入地址 (獲取 SOCKS5 格式地址並去除結尾的端口部分)
	addr, err := ToSocksAddr(targetHost, targetPort)
	if err != nil {
		return nil, err
	}
	// ToSocksAddr 返回 [Type][Addr...][Port(2)]，我們只需要地址部分
	buf.Write(addr[:len(addr)-2])

	return buf.Bytes(), nil
}
