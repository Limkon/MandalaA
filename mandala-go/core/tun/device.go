package tun

import (
	"fmt"
	"log"
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
	log.Printf("GoLog: [Device] Init - FD: %d, MTU: %d", fd, mtu)

	// 1. 强制设置为非阻塞模式
	if err := syscall.SetNonblock(fd, true); err != nil {
		log.Printf("GoLog: [Device] CRITICAL - Failed to set non-blocking: %v", err)
		return nil, fmt.Errorf("set nonblock: %v", err)
	}

	f := os.NewFile(uintptr(fd), "tun")
	
	return &Device{
		fd:   fd,
		file: f,
		mtu:  mtu,
	}, nil
}

func (d *Device) LinkEndpoint() stack.LinkEndpoint {
	// [关键修复] 创建 Endpoint 配置
	ep, err := fdbased.New(&fdbased.Options{
		FDs: []int{d.fd},
		MTU: d.mtu,
		
		// 必须关闭 EthernetHeader，因为是 L3 TUN 设备
		EthernetHeader: false,
		
		// [必须为 true] 告诉 gVisor 不要校验接收到的包，直接认为是有效的。
		// Android 系统往往不计算伪头部校验和，设为 false 会导致所有入站包被丢弃(RX=0)。
		RXChecksumOffload: true, 
		
		// [必须为 false] 告诉 gVisor 在发给 Android 前必须计算好校验和。
		// Android 内核若收到校验和错误的包会丢弃。
		TXChecksumOffload: false,
	})

	if err != nil {
		log.Printf("GoLog: [Device] Failed to create endpoint: %v", err)
		return nil
	}

	log.Println("GoLog: [Device] Endpoint created. Checksum Offload Corrected.")
	return ep
}

func (d *Device) Close() {
	log.Println("GoLog: [Device] Closing...")
	if d.file != nil {
		d.file.Close()
	}
}
