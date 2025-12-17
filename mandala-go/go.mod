module mandala

go 1.20

require (
	// [核心修复] 这里的版本必须与 CI 中 go install 的版本完全一致
	golang.org/x/mobile v0.0.0-20231127183840-76ac6878050a
	golang.org/x/sys v0.15.0
	golang.org/x/time v0.5.0
	gvisor.dev/gvisor v0.0.0-20231023213702-2691a8f9b1cf
)

// 保持 gVisor 锁定
replace gvisor.dev/gvisor => gvisor.dev/gvisor v0.0.0-20231023213702-2691a8f9b1cf
