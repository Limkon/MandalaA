package tun

import (
	"context"
	"fmt"
	"io"
	"log"
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

// Stack 封装了用户态网络栈和代理逻辑
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

func StartStack(fd int, cfg *config.OutboundConfig) (*Stack, error) {
	// 1. 初始化网络栈
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	}
	s := stack.New(opts) // s 是 *stack.Stack

	// 2. 创建 TUN 设备 (传入 MTU 1500)
	dev, err := NewDevice(fd, 1500)
	if err != nil {
		return nil, fmt.Errorf("创建 TUN 设备失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	dialer := proxy.NewDialer(cfg)

	st := &Stack{
		stack:  s,
		device: dev,
		dialer: dialer,
		config: cfg,
		nat:    NewUDPNatManager(dialer, cfg),
		ctx:    ctx,
		cancel: cancel,
	}

	// 3. 创建 NIC
	nicID := tcpip.NICID(1)
	if err := s.CreateNIC(nicID, dev); err != nil {
		return nil, fmt.Errorf("CreateNIC 失败: %v", err)
	}

	// 4. 设置路由表
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		},
	})

	// 5. 设置传输层处理
	// [注意] NewForwarder 第一个参数需要 *stack.Stack
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(s, 0, 10, st.handleTCP).HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udp.NewForwarder(s, st.handleUDP).HandlePacket)

	log.Println("GoLog: 网络栈启动完成")
	return st, nil
}

// handleTCP 处理 TCP 流量
func (s *Stack) handleTCP(r *tcp.ForwarderRequest) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[TCP] Panic 恢复: %v", err)
		}
	}()

	id := r.ID()
	targetHost := id.LocalAddress.String()
	targetPort := int(id.LocalPort)

	// 连接远程代理
	remoteConn, dialErr := s.dialer.Dial()
	if dialErr != nil {
		r.Complete(true)
		return
	}
	defer remoteConn.Close()

	// 握手
	var payload []byte
	var hErr error
	isVless := false

	switch strings.ToLower(s.config.Type) {
	case "mandala":
		client := protocol.NewMandalaClient(s.config.Username, s.config.Password)
		noiseSize := 0
		if s.config.Settings != nil && s.config.Settings.Noise {
			noiseSize = s.config.Settings.NoiseSize
		}
		payload, hErr = client.BuildHandshakePayload(targetHost, targetPort, noiseSize)
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

	// 创建本地端点
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)

	localConn := gonet.NewTCPConn(&wq, ep)
	defer localConn.Close()

	// 双向转发
	go func() {
		io.Copy(localConn, remoteConn)
		localConn.CloseWrite()
	}()

	io.Copy(remoteConn, localConn)
}

// handleUDP 处理 UDP 流量
func (s *Stack) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	dstPort := id.LocalPort

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return
	}

	// [修复] gonet.NewUDPConn 需要传入 gvisor stack 实例
	localConn := gonet.NewUDPConn(s.stack, &wq, ep)

	if dstPort == 53 {
		go s.handleRemoteDNS(localConn)
		return
	}

	targetIP := id.LocalAddress.String()
	targetPort := int(dstPort)
	key := fmt.Sprintf("%s:%d", targetIP, targetPort)

	session, errNat := s.nat.GetOrCreate(key, localConn, targetIP, targetPort)
	if errNat != nil {
		localConn.Close()
		return
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := localConn.Read(buf)
			if err != nil {
				return
			}
			session.RemoteConn.Write(buf[:n])
		}
	}()
}

// handleRemoteDNS 处理 DNS
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

	switch strings.ToLower(s.config.Type) {
	case "mandala":
		client := protocol.NewMandalaClient(s.config.Username, s.config.Password)
		noiseSize := 0
		if s.config.Settings != nil && s.config.Settings.Noise {
			noiseSize = s.config.Settings.NoiseSize
		}
		payload, _ = client.BuildHandshakePayload("8.8.8.8", 53, noiseSize)
	case "trojan":
		payload, _ = protocol.BuildTrojanPayload(s.config.Password, "8.8.8.8", 53)
	case "vless":
		payload, _ = protocol.BuildVlessPayload(s.config.UUID, "8.8.8.8", 53)
		isVless = true
	case "shadowsocks":
		payload, _ = protocol.BuildShadowsocksPayload("8.8.8.8", 53)
	case "socks", "socks5":
		protocol.HandshakeSocks5(proxyConn, s.config.Username, s.config.Password, "8.8.8.8", 53)
	}

	if len(payload) > 0 {
		proxyConn.Write(payload)
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
}

func (s *Stack) Close() error {
	s.cancel()
	s.closeOnce.Do(func() {
		if s.stack != nil {
			s.stack.Close()
		}
		if s.device != nil {
			s.device.Close()
		}
	})
	return nil
}
