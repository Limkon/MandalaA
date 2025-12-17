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
	"gvisor.dev/gvisor/pkg/tcpip/header"
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
	// 验证标记，确保 CI 跑的是新代码
	fmt.Println("DEBUG: Build Version 2025-Fixed-Import")

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
	// 使用 header.IPv4EmptySubnet (即 0.0.0.0/0)
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet, 
			NIC:         nicID,
		},
	})

	s.SetPromiscuousMode(nicID, true)

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
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)

	localConn := gonet.NewTCPConn(&wq, ep)
	defer localConn.Close()

	remoteConn, dialErr := s.dialer.Dial()
	if dialErr != nil {
		return
	}
	defer remoteConn.Close()

	var handshakeErr error
	var handshakePayload []byte

	switch s.config.Type {
	case "mandala":
		client := protocol.NewMandalaClient(s.config.Username, s.config.Password)
		handshakePayload, handshakeErr = client.BuildHandshakePayload(targetIP.String(), int(targetPort))
	default:
	}

	if handshakeErr != nil {
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

	// [重要] 3個參數，適配您鎖定的舊版 gVisor
	localConn := gonet.NewUDPConn(s.stack, &wq, ep)

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
