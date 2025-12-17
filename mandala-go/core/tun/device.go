package tun

import (
	"fmt"
	"os"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip" // 必須引入
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Device struct {
	fd      int
	mtu     uint32
	linkEP  stack.LinkEndpoint
	closeCh chan struct{}
	closed  uint32
}

func NewDevice(fd int, mtu uint32) (*Device, error) {
	if fd < 0 {
		return nil, fmt.Errorf("invalid fd: %d", fd)
	}

	ep, err := fdbased.New(&fdbased.Options{
		FDs: []int{fd},
		MTU: mtu,
		EthernetHeader: false, 
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

func (d *Device) LinkEndpoint() stack.LinkEndpoint {
	return d.linkEP
}

func (d *Device) Close() error {
	if !atomic.CompareAndSwapUint32(&d.closed, 0, 1) {
		return nil
	}
	close(d.closeCh)
	return os.NewFile(uintptr(d.fd), "tun").Close()
}
