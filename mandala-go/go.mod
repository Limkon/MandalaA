module mandala

go 1.20

require (
	golang.org/x/sys v0.15.0
	golang.org/x/time v0.5.0
	golang.org/x/net v0.19.0
	// 固定到 2024 年 4 月中旬的 commit
	// 这个版本已包含项目所需的全部新 API（解决 undefined 和参数/接口不匹配错误）
	// 同时在上游仓库中有效，且尚未引入导致 gomobile 包冲突的测试文件问题
	gvisor.dev/gvisor v0.0.0-20240422014219-5f3405a66183
)

// 移除所有 replace 指令
