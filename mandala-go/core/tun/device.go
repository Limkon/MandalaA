package tun

import (
	"os"
	"syscall"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Device 实现 stack.LinkEndpoint 接口
type Device struct {
	fd         int
	mtu        uint32
	dispatcher stack.NetworkDispatcher
}

// [修复] 增加 mtu 参数
func NewDevice(fd int, mtu uint32) (*Device, error) {
	return &Device{
		fd:  fd,
		mtu: mtu,
	}, nil
}

// 实现 LinkEndpoint 接口所需的方法

func (d *Device) MTU() uint32 {
	return d.mtu
}

func (d *Device) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

func (d *Device) MaxHeaderLength() uint16 {
	return 0
}

func (d *Device) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (d *Device) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	// 简单实现：遍历写入
	count := 0
	for _, pkt := range pkts.AsSlice() {
		if err := d.writePacket(pkt); err != nil {
			break
		}
		count++
	}
	return count, nil
}

func (d *Device) writePacket(pkt *stack.PacketBuffer) tcpip.Error {
	// 获取数据视图
	views := pkt.ToView().ToVectorisedView()
	// 将数据合并为一个字节切片
	data := views.ToView()

	// 写入 TUN 设备
	if _, err := syscall.Write(d.fd, data); err != nil {
		return &tcpip.ErrInvalidOption{} // 返回通用错误
	}
	return nil
}

func (d *Device) Attach(dispatcher stack.NetworkDispatcher) {
	d.dispatcher = dispatcher
	// 启动读取循环
	// 在 gVisor 集成中，我们需要一个机制将读取到的数据注入 dispatcher。
	go d.readLoop()
}

func (d *Device) IsAttached() bool {
	return d.dispatcher != nil
}

func (d *Device) Wait() {}

// [修复] 实现缺失的 ARPHardwareType 方法
func (d *Device) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (d *Device) AddHeader(pkt *stack.PacketBuffer) {}
func (d *Device) ParseHeader(pkt *stack.PacketBuffer) bool { return true }

// readLoop 从文件描述符读取数据并分发给网络栈
func (d *Device) readLoop() {
	buf := make([]byte, d.mtu)
	for {
		n, err := syscall.Read(d.fd, buf)
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}

		// 复制数据，因为 buffer 会被重用
		data := make([]byte, n)
		copy(data, buf[:n])

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(buffer.View(data)),
		})

		// 判断 IP 版本 (IPv4 vs IPv6)
		var proto tcpip.NetworkProtocolNumber
		if n > 0 {
			switch data[0] >> 4 {
			case 4:
				proto = header.IPv4ProtocolNumber
			case 6:
				proto = header.IPv6ProtocolNumber
			default:
				continue
			}
		}

		if d.dispatcher != nil {
			d.dispatcher.DeliverNetworkPacket(proto, pkt)
		}
		pkt.DecRef()
	}
}

func (d *Device) Close() error {
	return os.NewFile(uintptr(d.fd), "tun").Close()
}
