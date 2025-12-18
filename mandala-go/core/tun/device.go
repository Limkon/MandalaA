package tun

import (
	"fmt"
	"log" // 必须用 log 才能在 Logcat 看到
	"os"
	"syscall"

	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Device struct {
	fd   int
	file *os.File
	mtu  uint32
}

func NewDevice(fd int, mtu uint32) (*Device, error) {
	log.Printf("GoLog: Device Init - FD: %d, MTU: %d", fd, mtu)

	// [核心修复] 强制将 FD 设置为非阻塞模式 (Non-Blocking)
	// gVisor 的 fdbased endpoint 严重依赖非阻塞 IO。
	// 如果不加这一行，Read() 可能会永久阻塞，导致整个网络栈“假死”。
	if err := syscall.SetNonblock(fd, true); err != nil {
		log.Printf("GoLog: CRITICAL ERROR - Failed to set non-blocking: %v", err)
		return nil, fmt.Errorf("set nonblock: %v", err)
	}
	log.Println("GoLog: Device - SetNonblock(true) success")

	f := os.NewFile(uintptr(fd), "tun")
	
	return &Device{
		fd:   fd,
		file: f,
		mtu:  mtu,
	}, nil
}

func (d *Device) LinkEndpoint() stack.LinkEndpoint {
	// 创建基于文件描述符的 Endpoint
	// 注意：这里会将我们在 Java 层创建的 TUN 设备交给 gVisor 接管
	ep, err := fdbased.New(&fdbased.Options{
		FDs: []int{d.fd},
		MTU: d.mtu,
		// gVisor 会自动处理以太网头（如果是 TAP）或 IP 头（如果是 TUN）
		// 在 Android VPN 模式下，我们通常处理的是纯 IP 包
	})

	if err != nil {
		// 注意：旧版 gVisor 的 New 可能不会返回 error，如果编译报错请删掉 error 处理
		log.Printf("GoLog: Failed to create fdbased endpoint: %v", err)
		return nil
	}

	log.Println("GoLog: Device - LinkEndpoint created successfully, packet loop starting...")
	return ep
}

func (d *Device) Close() {
	log.Println("GoLog: Device Closing...")
	if d.file != nil {
		d.file.Close()
	}
}
