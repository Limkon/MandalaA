package protocol

// BuildShadowsocksPayload 构造 Shadowsocks 握手包
// 在 Mandala 架构中，Shadowsocks over TLS/WebSocket 只需要发送标准 SOCKS5 格式的目标地址
// 格式: [ATYP][ADDR][PORT]
func BuildShadowsocksPayload(targetHost string, targetPort int) ([]byte, error) {
	// 直接复用 utils.go 中的 ToSocksAddr，它生成的正是 SS 需要的格式
	return ToSocksAddr(targetHost, targetPort)
}
