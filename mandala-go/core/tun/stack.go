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
	closeOnce sync.Once // 防止重复关闭
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

	// 开启转发
	s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true)
	s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true)

	nicID := tcpip.NICID(1)

	if err := s.CreateNIC(nicID, dev.LinkEndpoint()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("创建网卡失败: %v", err)
	}

	// 开启 IP 欺骗 (Spoofing)
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

	// 标记是否需要 VLESS 响应处理
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

	// [新增] 如果是 VLESS，包装连接以剥离响应头
	if isVless {
		remoteConn = protocol.NewVlessConn(remoteConn)
	}

	// 3. 建立本地连接
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)

	localConn := gonet.NewTCPConn(&wq, ep)
	defer localConn.Close()

	// 4. 双向转发
	go func() {
		io.Copy(localConn, remoteConn)
		localConn.CloseWrite()
	}()

	io.Copy(remoteConn, localConn)
}

func (s *Stack) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	targetPort := int(id.LocalPort)

	// [DNS处理] 拦截 53 端口
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

	// UDP NAT 逻辑
	session, natErr := s.nat.GetOrCreate(srcKey, localConn, targetIP, targetPort)
	if natErr != nil {
		localConn.Close()
		return
	}

	// Local -> Remote 转发
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

	// 1. 连接代理
	proxyConn, err := s.dialer.Dial()
	if err != nil {
		log.Printf("[DNS] 代理连接失败: %v", err)
		return
	}
	defer proxyConn.Close()

	// 2. 发送握手 (固定转发到 8.8.8.8)
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
	}

	if _, err := proxyConn.Write(payload); err != nil {
		return
	}

	// 如果是 VLESS DNS 连接，也需要包装以剥离响应头
	if isVless {
		// 注意：此处 proxyConn 是 net.Conn 接口，需要 reassignment
		proxyConn = protocol.NewVlessConn(proxyConn)
	}

	// 3. 封装 DNS (2字节长度 + 数据)
	reqData := make([]byte, 2+n)
	reqData[0] = byte(n >> 8)
	reqData[1] = byte(n)
	copy(reqData[2:], buf[:n])

	if _, err := proxyConn.Write(reqData); err != nil {
		return
	}

	// 4. 读取响应
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(proxyConn, lenBuf); err != nil {
		return
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])

	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(proxyConn, respBuf); err != nil {
		return
	}

	// 5. 写回 Android
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
