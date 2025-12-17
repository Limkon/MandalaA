module mandala

go 1.20

require (
	golang.org/x/sys v0.15.0
	golang.org/x/time v0.5.0
	golang.org/x/net v0.19.0
	gvisor.dev/gvisor v0.0.0-20231202080848-1f48d6a80442 // 先写个占位，CI 会更新
)

// 强制替换为一个已知有效的、较新的 gVisor 版本
// 这个版本已经包含了 Subnet API 变更
replace gvisor.dev/gvisor => gvisor.dev/gvisor v0.0.0-20240408034247-4148b874457e
