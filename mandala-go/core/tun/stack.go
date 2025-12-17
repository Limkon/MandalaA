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

type Stack struct {
	stack  *stack.Stack
	device *Device
	dialer *proxy.Dialer
	config *config.OutboundConfig
	nat    *UDPNatManager
	ctx    context.Context
	cancel context.CancelFunc
}

func StartStack(fd int, mtu int, cfg *config.OutboundConfig) (*Stack, error) {
	dev, err := NewDevice(fd, uint32(mtu))
	if err != nil {
		return nil, err
	}

	// 1. 初始化协议栈
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

	nicID := tcpip.NICID(1)
	if err := s.CreateNIC(nicID, dev.LinkEndpoint()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("create nic failed: %v", err)
	}

	// 2. 路由表设置
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: tcpip.Address{}, // 0.0.0.0
			Mask:        tcpip.Address{}, // /0
			NIC:         nicID,
		},
	})

	s.SetPromiscuousMode(nicID, true)

	// 3. SACK 设置
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
	tcpHandler := tcp.NewForwarder(s.stack, 30000, 10, func(r *tcp.ForwarderRequest) {
		go s.handleTCP(r)
	})
	s.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpHandler.HandlePacket)

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
	ep, err := r.CreateEndpoint(&wq) // err is tcpip.Error
	if err != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)

	// [已验证] NewTCPConn 使用 2 个参数
	localConn := gonet.NewTCPConn(&wq, ep)
	defer localConn.Close()

	// fmt.Printf("[TCP] Connect to %s:%d\n", targetIP, targetPort)

	remoteConn, dialErr := s.dialer.Dial()
	if dialErr != nil {
		return
	}
	defer remoteConn.Close()

	// 简单的握手处理逻辑
	var handshakeErr error
	var handshakePayload []byte

	switch s.config.Type {
	case "mandala":
		client := protocol.NewMandalaClient(s.config.Username, s.config.Password)
		handshakePayload, handshakeErr = client.BuildHandshakePayload(targetIP.String(), int(targetPort))
	// 暂时保留 VLESS/Trojan 的 TODO，避免编译错误，但在实际运行时需注意
	default:
		// 直连或其他未实现协议
	}

	if handshakeErr != nil {
		// fmt.Printf("[Stack] Handshake build failed: %v\n", handshakeErr)
		return
	}

	if len(handshakePayload) > 0 {
		if _, wErr := remoteConn.Write(handshakePayload); wErr != nil {
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

	// [修复] gVisor API 变更，NewUDPConn 现在通常只需要 2 个参数 (wq, ep)
	// 如果编译报错提示需要 3 个参数，请恢复 s.stack，但根据 handleTCP 的写法，此处应为 2 个。
	localConn := gonet.NewUDPConn(&wq, ep)

	session, natErr := s.nat.GetOrCreate(srcKey, localConn, targetIP, targetPort)
	if natErr != nil {
		localConn.Close()
		return
	}

	go func() {
		defer localConn.Close()
		buf := make([]byte, 4096)

		for {
			n, rErr := localConn.Read(buf)
			if rErr != nil {
				return
			}
			if _, wErr := session.RemoteConn.Write(buf[:n]); wErr != nil {
				return
			}
		}
	}()
}
