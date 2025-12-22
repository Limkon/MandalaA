package tun

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

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

func init() {
	log.SetPrefix("GoLog: ")
}

type Stack struct {
	stack     *stack.Stack
	device    *Device
	dialer    *proxy.Dialer
	config    *config.OutboundConfig
	nat       *UDPNatManager
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

func StartStack(fd int, mtu int, cfg *config.OutboundConfig) (*Stack, error) {
	log.Printf("[Stack] 启动中 (FD: %d, MTU: %d, Type: %s)", fd, mtu, cfg.Type)

	dev, err := NewDevice(fd, uint32(mtu))
	if err != nil {
		return nil, err
	}

	// 1. 创建协议栈
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

	// [关键修复] 配置 TCP 协议栈选项
	// 启用 SACK (Selective Acknowledgment) 以提高丢包环境下的性能
	sackOpt := tcp.SACKEnabled(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt); err != nil {
		log.Printf("[Stack] Warning: Failed to enable SACK: %v", err)
	}

	// [关键修复] 增大默认发送缓冲区 (控制 Download 速度: Stack -> App)
	// 默认值可能太小，导致从代理接收的数据无法及时写入 TUN，导致下载慢/断流
	sndBufOpt := tcp.SendBufferSizeOption(2 * 1024 * 1024) // 2MB
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sndBufOpt); err != nil {
		log.Printf("[Stack] Warning: Failed to set SendBufferSize: %v", err)
	}

	// [关键修复] 增大默认接收缓冲区 (控制 Upload 速度: App -> Stack)
	rcvBufOpt := tcp.ReceiveBufferSizeOption(2 * 1024 * 1024) // 2MB
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvBufOpt); err != nil {
		log.Printf("[Stack] Warning: Failed to set ReceiveBufferSize: %v", err)
	}

	// 2. 配置网卡
	s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true)
	s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true)

	nicID := tcpip.NICID(1)
	if err := s.CreateNIC(nicID, dev.LinkEndpoint()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("创建网卡失败: %v", err)
	}

	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

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

func (s *Stack) startPacketHandling() {
	// [之前修复]
	// rcvWnd: 1MB (通告窗口大小)
	// maxInFlight: 2048 (最大并发握手)
	rcvWnd := 1 << 20
	maxInFlight := 2048

	tcpHandler := tcp.NewForwarder(s.stack, rcvWnd, maxInFlight, func(r *tcp.ForwarderRequest) {
		go s.handleTCP(r)
	})
	s.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpHandler.HandlePacket)

	udpHandler := udp.NewForwarder(s.stack, func(r *udp.ForwarderRequest) {
		s.handleUDP(r)
	})
	s.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpHandler.HandlePacket)
}

func (s *Stack) handleTCP(r *tcp.ForwarderRequest) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[TCP] Panic: %v", err)
		}
	}()

	id := r.ID()

	// 1. 拨号代理
	remoteConn, dialErr := s.dialer.Dial()
	if dialErr != nil {
		r.Complete(true)
		return
	}
	defer remoteConn.Close()

	// 2. 握手
	var payload []byte
	var hErr error
	targetHost := id.LocalAddress.String()
	targetPort := int(id.LocalPort)
	isVless := false

	switch strings.ToLower(s.config.Type) {
	case "mandala":
		client := protocol.NewMandalaClient(s.config.Username, s.config.Password)
		payload, hErr = client.BuildHandshakePayload(targetHost, targetPort)
	case "trojan":
		payload, hErr = protocol.BuildTrojanPayload(s.config.Password, targetHost, targetPort)
	case "vless":
		payload, hErr = protocol.BuildVlessPayload(s.config.UUID, targetHost, targetPort)
		isVless = true
	case "shadowsocks":
		payload, hErr = protocol.BuildShadowsocksPayload(targetHost, targetPort)
	case "socks", "socks5":
		hErr = protocol.HandshakeSocks5(remoteConn, s.config.Username, s.config.Password, targetHost, targetPort)
	}

	if hErr != nil {
		r.Complete(true)
		return
	}

	if len(payload) > 0 {
		if _, err := remoteConn.Write(payload); err != nil {
			r.Complete(true)
			return
		}
	}

	if isVless {
		remoteConn = protocol.NewVlessConn(remoteConn)
	}

	// 3. 建立本地连接 (gonet)
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)

	// gonet.NewTCPConn 会使用之前配置的默认 Buffer Size (现在是 2MB)
	localConn := gonet.NewTCPConn(&wq, ep)
	defer localConn.Close()

	// 4. 双向转发
	go func() {
		// Data: Stack -> Remote (Upload)
		io.Copy(remoteConn, localConn)
		// 如果本地关闭了写(App关闭连接)，则关闭远程的连接
		// 注意: io.Copy 结束通常意味着 Read 到了 EOF
	}()

	// Data: Remote -> Stack (Download)
	// 这里是最容易堵塞的地方，如果 localConn 的写缓冲区太小
	io.Copy(localConn, remoteConn)
	localConn.CloseWrite()
}

func (s *Stack) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	targetPort := int(id.LocalPort)

	if targetPort == 53 {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return
		}
		localConn := gonet.NewUDPConn(s.stack, &wq, ep)
		go s.handleRemoteDNS(localConn)
		return
	}

	targetIP := net.IP(id.LocalAddress.AsSlice()).String()
	srcKey := fmt.Sprintf("%s:%d->%s:%d", id.RemoteAddress.String(), id.RemotePort, targetIP, targetPort)

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return
	}

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
			localConn.SetDeadline(time.Now().Add(60 * time.Second))
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

func (s *Stack) handleRemoteDNS(conn *gonet.UDPConn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	proxyConn, err := s.dialer.Dial()
	if err != nil {
		log.Printf("[DNS] 代理连接失败: %v", err)
		return
	}
	defer proxyConn.Close()

	var payload []byte
	isVless := false

	switch strings.ToLower(s.config.Type) {
	case "mandala":
		client := protocol.NewMandalaClient(s.config.Username, s.config.Password)
		payload, _ = client.BuildHandshakePayload("8.8.8.8", 53)
	case "trojan":
		payload, _ = protocol.BuildTrojanPayload(s.config.Password, "8.8.8.8", 53)
	case "vless":
		payload, _ = protocol.BuildVlessPayload(s.config.UUID, "8.8.8.8", 53)
		isVless = true
	case "shadowsocks":
		payload, _ = protocol.BuildShadowsocksPayload("8.8.8.8", 53)
	case "socks", "socks5":
		if err := protocol.HandshakeSocks5(proxyConn, s.config.Username, s.config.Password, "8.8.8.8", 53); err != nil {
			log.Printf("[DNS] Socks5握手失败: %v", err)
			return
		}
	}

	if len(payload) > 0 {
		if _, err := proxyConn.Write(payload); err != nil {
			return
		}
	}

	if isVless {
		proxyConn = protocol.NewVlessConn(proxyConn)
	}

	reqData := make([]byte, 2+n)
	reqData[0] = byte(n >> 8)
	reqData[1] = byte(n)
	copy(reqData[2:], buf[:n])

	if _, err := proxyConn.Write(reqData); err != nil {
		return
	}

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(proxyConn, lenBuf); err != nil {
		return
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])

	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(proxyConn, respBuf); err != nil {
		return
	}

	conn.Write(respBuf)
	log.Printf("[DNS] 解析完成")
}

func (s *Stack) Close() {
	s.closeOnce.Do(func() {
		log.Println("[Stack] Stopping...")
		if s.cancel != nil {
			s.cancel()
		}
		time.Sleep(100 * time.Millisecond)
		if s.device != nil {
			s.device.Close()
		}
		if s.stack != nil {
			s.stack.Close()
		}
		log.Println("[Stack] Stopped.")
	})
}
