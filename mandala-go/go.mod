module mandala

go 1.20

require (
	// 工具依赖 (由 tools.go 守护)
	golang.org/x/mobile v0.0.0-20231127183840-76ac6878050a
	golang.org/x/mod v0.14.0 // 间接依赖
	golang.org/x/tools v0.16.0 // 间接依赖
	
	// 项目依赖
	golang.org/x/sys v0.15.0
	golang.org/x/time v0.5.0
	gvisor.dev/gvisor v0.0.0-20231023213702-2691a8f9b1cf
)

// 锁定 gVisor 到 2023 稳定版
replace gvisor.dev/gvisor => gvisor.dev/gvisor v0.0.0-20231023213702-2691a8f9b1cf
