module mandala

go 1.20

require (
	// 工具依赖
	golang.org/x/mobile v0.0.0-20231127183840-76ac6878050a
	golang.org/x/mod v0.14.0 // 间接依赖
	golang.org/x/tools v0.16.0 // 间接依赖

	// [关键修改] 升级以下两个库以支持 ECH
	github.com/refraction-networking/utls v1.6.7
	golang.org/x/net v0.27.0

	// 项目依赖
	golang.org/x/sys v0.22.0
	golang.org/x/time v0.5.0
	gvisor.dev/gvisor v0.0.0-20231023213702-2691a8f9b1cf
)

// 锁定 gVisor 到 2023 稳定版
replace gvisor.dev/gvisor => gvisor.dev/gvisor v0.0.0-20231023213702-2691a8f9b1cf
