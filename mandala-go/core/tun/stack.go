package tun

import (
	"context"
	"fmt"
	"io"
	"net"

	"mandala/core/config"
	"mandala/core/protocol"
	"mandala/core/proxy"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Stack 负责管理网络栈
type Stack struct {
	stack  *stack.Stack
	device *Device
	dialer *proxy.Dialer
	config *config.OutboundConfig
	nat    *UDPNatManager
	ctx    context.Context
	cancel context.CancelFunc
}

// StartStack 初始化网络栈 (适配 2023 稳定版 API)
func StartStack(fd int, mtu int, cfg *config.OutboundConfig) (*Stack, error) {
	// 1. 创建设备
	dev, err := NewDevice(fd, uint32(mtu))
	if err != nil {
		return nil, err
	}

	// 2. 初始化协议栈
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})

	// 3. 创建 NIC
	nicID := tcpip.NICID(1)
	if err := s.CreateNIC(nicID, dev.LinkEndpoint()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("create nic failed: %v", err)
	}

	// 4. 设置路由 (使用旧版 API: Address + Mask)
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: tcpip.Address{}, // 0.0.0.0
			Mask:        tcpip.Address{}, // /0
			NIC:         nicID,
		},
	})

	s.SetPromiscuousMode(nicID, true)
	
	// 5. TCP 选项 (旧版 API: 布尔值)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, tcp.SACKEnabled(true))

	ctx, cancel := context.WithCancel(context.Background())
	
	dialer := proxy.NewDialer(cfg)

	tStack := &Stack{
		stack:  s,
		device: dev,
		dialer: dialer,
		config: cfg,
		nat:    NewUDPNatManager(dialer, cfg),
		ctx:    ctx,
		cancel: cancel,
	}

	tStack.startPacketHandling()

	return tStack, nil
}

func (s *Stack) Close() {
	s.cancel()
	if s.device != nil {
		s.device.Close()
	}
	if s.stack != nil {
		s.stack.Close()
	}
}

func (s *Stack) startPacketHandling() {
	// TCP 处理
	tcpHandler := tcp.NewForwarder(s.stack, 30000, 10, func(r *tcp.ForwarderRequest) {
		go s.handleTCP(r)
	})
	s.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpHandler.HandlePacket)

	// UDP 处理
	udpHandler := udp.NewForwarder(s.stack, func(r *udp.ForwarderRequest) {
		s.handleUDP(r)
	})
	s.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpHandler.HandlePacket)
}

func (s *Stack) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	targetIP := net.IP(id.LocalAddress.AsSlice())
	targetPort := id.LocalPort
	
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)

	localConn := gonet.NewTCPConn(&wq, ep)
	defer localConn.Close()
	
	fmt.Printf("[TCP] Connect to %s:%d\n", targetIP, targetPort)

	remoteConn, err := s.dialer.Dial()
	if err != nil {
		return
	}
	defer remoteConn.Close()

	if s.config.Type == "mandala" {
		client := protocol.NewMandalaClient(s.config.Username, s.config.Password)
		payload, err := client.BuildHandshakePayload(targetIP.String(), int(targetPort))
		if err != nil {
			return 
		}
		if _, err := remoteConn.Write(payload); err != nil {
			return
		}
	}

	go io.Copy(remoteConn, localConn)
	io.Copy(localConn, remoteConn)
}

func (s *Stack) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	targetIP := net.IP(id.LocalAddress.AsSlice()).String()
	targetPort := int(id.LocalPort)
	
	srcKey := fmt.Sprintf("%s:%d->%s:%d", 
		id.RemoteAddress.String(), id.RemotePort,
		targetIP, targetPort)

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return
	}
	// 旧版 API: NewUDPConn 需要 stack 参数
	localConn := gonet.NewUDPConn(s.stack, &wq, ep)

	session, err := s.nat.GetOrCreate(srcKey, localConn, targetIP, targetPort)
	if err != nil {
		localConn.Close()
		return
	}

	go func() {
		defer localConn.Close()
		buf := make([]byte, 4096)
		n, err := localConn.Read(buf)
		if err != nil {
			return 
		}
		// 写入数据
		session.RemoteConn.Write(buf[:n])
		// 实际上这里应该更新 session.LastActive，但为了避免跨包引用复杂性，我们暂且依赖 nat.go 的读循环来更新
	}()
}
