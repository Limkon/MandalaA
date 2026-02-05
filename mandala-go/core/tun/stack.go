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
	tcpHandler := tcp.NewForwarder(s.stack, 30000, 10, func(r *tcp.ForwarderRequest) {
		go s.handleTCP(r)
	})
	s.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpHandler.HandlePacket)

	udpHandler := udp.NewForwarder(s.stack, func(r *udp.ForwarderRequest) {
		go s.handleUDP(r)
	})
	s.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpHandler.HandlePacket)
}

func (s *Stack) handleTCP(r *tcp.ForwarderRequest) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[TCP] Panic 恢复: %v", err)
		}
	}()

	id := r.ID()

	// 1. 拨号代理
	remoteConn, dialErr := s.dialer.Dial()
	if dialErr != nil {
		r.Complete(true)
		return
	}

	// 2. 握手逻辑
	var payload []byte
	var hErr error
	targetHost := id.LocalAddress.String()
	targetPort := int(id.LocalPort)
	isVless := false

	switch strings.ToLower(s.config.Type) {
	case "mandala":
		// [Fix] 兼容性修复：Mandala 的密钥通常是 UUID
		// 如果 Password 字段为空，尝试使用 UUID 字段
		password := s.config.Password
		if password == "" {
			password = s.config.UUID
		}

		client := protocol.NewMandalaClient(s.config.Username, password)
		payload, hErr = client.BuildHandshakePayload(targetHost, targetPort, s.config.Settings.Noise)

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
		remoteConn.Close()
		r.Complete(true)
		return
	}

	if len(payload) > 0 {
		if _, err := remoteConn.Write(payload); err != nil {
			remoteConn.Close()
			r.Complete(true)
			return
		}
	}

	if isVless {
		remoteConn = protocol.NewVlessConn(remoteConn)
	}

	// 3. 建立本地连接
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		remoteConn.Close()
		r.Complete(true)
		return
	}
	r.Complete(false)

	localConn := gonet.NewTCPConn(&wq, ep)

	// 双向关闭逻辑
	closeAll := func() {
		localConn.Close()
		remoteConn.Close()
	}

	go func() {
		defer closeAll()
		io.Copy(localConn, remoteConn)
	}()

	go func() {
		defer closeAll()
		io.Copy(remoteConn, localConn)
	}()
}

func (s *Stack) handleUDP(r *udp.ForwarderRequest) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[UDP] Panic 恢复: %v", err)
		}
	}()

	id := r.ID()
	targetPort := int(id.LocalPort)

	// [DNS] 拦截 53 端口
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

	// NAT 转发维持
	go func() {
		defer localConn.Close()
		buf := make([]byte, 4096)
		for {
			localConn.SetDeadline(time.Now().Add(60 * time.Second))
			n, rErr := localConn.Read(buf)
			if rErr != nil {
				return
			}
			if session.RemoteConn != nil {
				if _, wErr := session.RemoteConn.Write(buf[:n]); wErr != nil {
					return
				}
			}
		}
	}()
}

func (s *Stack) handleRemoteDNS(localConn *gonet.UDPConn) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[DNS] Panic 恢复: %v", err)
		}
		if localConn != nil {
			localConn.Close()
		}
	}()
	
	localConn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	n, err := localConn.Read(buf)
	if err != nil {
		return
	}

	// 1. 建立新连接
	proxyConn, err := s.dialer.Dial()
	if err != nil {
		log.Printf("[DNS] 代理拨号失败: %v", err)
		return
	}
	if proxyConn == nil {
		return
	}
	defer proxyConn.Close()

	// 2. 握手
	var payload []byte
	isVless := false
	
	switch strings.ToLower(s.config.Type) {
	case "mandala":
		// [Fix] DNS 部分也要修复
		password := s.config.Password
		if password == "" {
			password = s.config.UUID
		}

		client := protocol.NewMandalaClient(s.config.Username, password)
		payload, _ = client.BuildHandshakePayload("8.8.8.8", 53, s.config.Settings.Noise)
	case "trojan":
		payload, _ = protocol.BuildTrojanPayload(s.config.Password, "8.8.8.8", 53)
	case "vless":
		payload, _ = protocol.BuildVlessPayload(s.config.UUID, "8.8.8.8", 53)
		isVless = true
	case "shadowsocks":
		payload, _ = protocol.BuildShadowsocksPayload("8.8.8.8", 53)
	case "socks", "socks5":
		if err := protocol.HandshakeSocks5(proxyConn, s.config.Username, s.config.Password, "8.8.8.8", 53); err != nil {
			log.Printf("[DNS] Socks5 握手失败: %v", err)
			return
		}
	}

	if len(payload) > 0 {
		if _, err := proxyConn.Write(payload); err != nil {
			return
		}
	}

	var finalConn net.Conn = proxyConn
	if isVless {
		finalConn = protocol.NewVlessConn(proxyConn)
	}

	// 3. 转发 DNS 请求 (RFC 1035 TCP DNS 格式)
	reqData := make([]byte, 2+n)
	reqData[0] = byte(n >> 8)
	reqData[1] = byte(n)
	copy(reqData[2:], buf[:n])

	finalConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := finalConn.Write(reqData); err != nil {
		return
	}

	// 4. 读取响应长度
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(finalConn, lenBuf); err != nil {
		return
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if respLen <= 0 || respLen > 1500 {
		return
	}

	// 5. 读取响应体
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(finalConn, respBuf); err != nil {
		return
	}

	// 6. 写回本地
	localConn.Write(respBuf)
}

func (s *Stack) Close() {
	s.closeOnce.Do(func() {
		log.Println("[Stack] 正在停止网络栈...")

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

		log.Println("[Stack] 网络栈已停止。")
	})
}
