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
	rcvWnd := 0
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

	remoteConn, dialErr := s.dialer.Dial()
	if dialErr != nil {
		r.Complete(true)
		return
	}
	defer remoteConn.Close()

	var payload []byte
	var hErr error
	targetHost := id.LocalAddress.String()
	targetPort := int(id.LocalPort)

	isWebSocket := s.config.Transport != nil && s.config.Transport.Type == "ws"

	switch strings.ToLower(s.config.Type) {
	case "mandala":
		client := protocol.NewMandalaClient(s.config.Username, s.config.Password)
		payload, hErr = client.BuildHandshakePayload(targetHost, targetPort)
	case "trojan":
		payload, hErr = protocol.BuildTrojanPayload(s.config.Password, targetHost, targetPort)
	case "vless":
		payload, hErr = protocol.BuildVlessPayload(s.config.UUID, targetHost, targetPort)
	case "shadowsocks":
		payload, hErr = protocol.BuildShadowsocksPayload(targetHost, targetPort)
		// Shadowsocks 某些实现（如 Cloudflare Worker）可能返回少量响应头，我们稍后统一处理
	case "socks", "socks5":
		hErr = protocol.HandshakeSocks5(remoteConn, s.config.Username, s.config.Password, targetHost, targetPort)
	}

	if hErr != nil {
		log.Printf("[TCP] Handshake failed for %s:%d: %v", targetHost, targetPort, hErr)
		r.Complete(true)
		return
	}

	// 发送握手 payload（如果有）
	if len(payload) > 0 {
		if _, err := remoteConn.Write(payload); err != nil {
			log.Printf("[TCP] Write payload failed: %v", err)
			r.Complete(true)
			return
		}
	}

	// 协议特定的响应头剥离
	switch strings.ToLower(s.config.Type) {
	case "vless":
		if !isWebSocket {
			remoteConn = protocol.NewVlessConn(remoteConn)
		}
	case "socks", "socks5":
		// HandshakeSocks5 已经完整读取并验证了响应，无需额外处理
	case "shadowsocks":
		// 主动读取并丢弃可能的预响应（某些实现会发 0-几百字节）
		buf := make([]byte, 1024)
		remoteConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _ := remoteConn.Read(buf)
		if n > 0 {
			log.Printf("[SS] Discarded %d bytes of pre-response", n)
		}
		remoteConn.SetReadDeadline(time.Time{})
	default:
		// 其他协议（如 mandala/trojan）无响应头
	}

	// 创建 gVisor 端的本地连接
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		log.Printf("[TCP] CreateEndpoint failed: %v", err)
		r.Complete(true)
		return
	}

	localConn := gonet.NewTCPConn(&wq, ep)
	defer localConn.Close()

	// 双向转发
	var wg sync.WaitGroup
	wg.Add(2)

	// 上行：App -> Remote
	go func() {
		defer wg.Done()
		n, err := io.Copy(remoteConn, localConn)
		log.Printf("[TCP] Up: %d bytes, err=%v", n, err)
		if cw, ok := remoteConn.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()

	// 下行：Remote -> App
	go func() {
		defer wg.Done()
		n, err := io.Copy(localConn, remoteConn)
		log.Printf("[TCP] Down: %d bytes, err=%v", n, err)
		localConn.CloseWrite()
	}()

	// 等待上传和下载都完成
	wg.Wait()

	// 通知 gVisor 连接已完成
	r.Complete(false)
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
		localConn := gonet.NewUDPConn(&wq, ep)
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
		return
	}
	defer proxyConn.Close()

	var payload []byte
	isVless := false
	isWebSocket := s.config.Transport != nil && s.config.Transport.Type == "ws"

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
			return
		}
	}

	if len(payload) > 0 {
		if _, err := proxyConn.Write(payload); err != nil {
			return
		}
	}

	if isVless && !isWebSocket {
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
	})
}
