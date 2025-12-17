package tun

import (
	"fmt"
	"os"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Device 包装了 Android 的 VPN 文件描述符
type Device struct {
	fd      int
	mtu     uint32
	linkEP  stack.LinkEndpoint
	closeCh chan struct{}
	closed  uint32
}

// NewDevice 创建一个新的 TUN 设备包装器
func NewDevice(fd int, mtu uint32) (*Device, error) {
	// 验证 FD 是否有效
	if fd < 0 {
		return nil, fmt.Errorf("invalid fd: %d", fd)
	}

	// 创建 gVisor 的基于 FD 的链路端点
	// PacketDispatchMode: 这里只需要基本的读写
	ep, err := fdbased.New(&fdbased.Options{
		FDs: []int{fd},
		MTU: mtu,
		// Android VPN 通常没有以太网头，是纯 IP 包
		EthernetHeader: false, 
		// 自定义关闭回调，防止 double close
		ClosedFunc: func(e tcpip.Error) {},
	})
	if err != nil {
		return nil, fmt.Errorf("create endpoint failed: %v", err)
	}

	return &Device{
		fd:      fd,
		mtu:     mtu,
		linkEP:  ep,
		closeCh: make(chan struct{}),
	}, nil
}

// LinkEndpoint 返回 gVisor 需要的链路端点接口
func (d *Device) LinkEndpoint() stack.LinkEndpoint {
	return d.linkEP
}

// Close 关闭设备
func (d *Device) Close() error {
	if !atomic.CompareAndSwapUint32(&d.closed, 0, 1) {
		return nil
	}
	close(d.closeCh)
	// 关闭文件描述符
	return os.NewFile(uintptr(d.fd), "tun").Close()
}