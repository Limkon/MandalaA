module mandala

go 1.20

require (
	golang.org/x/sys v0.15.0
	golang.org/x/time v0.5.0
	// [方案3核心] 强制锁定 gVisor 到 2023.12 的稳定版
	// 这是 tun2socks 和 WireGuard 生态目前广泛使用的兼容版本
	gvisor.dev/gvisor v0.0.0-20231202080848-1f48d6a80442
	
	// 引入 WireGuard 的 tun 模块（可选，但在处理 Android FD 时非常稳健）
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173
)
