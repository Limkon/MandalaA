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
	// 1. 初始化网络栈选项
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	}
	
	// 创建 gVisor 协议栈实例
	s := stack.New(opts)

	// 2. 创建 TUN 设备适配器 (传入 MTU 1500)
	// [修复] NewDevice 签名已更新，传入 MTU
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

	// 4. 设置默认路由
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

	// 5. 设置传输层处理器
	// [修复] 这里 s 是 *stack.Stack，直接传入 NewForwarder
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(s, 0, 10, st.handleTCP).HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udp.NewForwarder(s, st.handleUDP).HandlePacket)

	log.Println("GoLog: 网络栈启动完成")
	return st, nil
}

// handleTCP 处理 TCP 连接请求
func (s *Stack) handleTCP(r *tcp.ForwarderRequest) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[TCP] Panic 恢复: %v", err)
		}
	}()

	id := r.ID()
	// 获取目标地址
	targetHost := id.LocalAddress.String()
	targetPort := int(id.LocalPort)

	// 1. 拨号远程代理服务器
	remoteConn, dialErr := s.dialer.Dial()
	if dialErr != nil {
		r.Complete(true) // 发送 RST 拒绝连接
		return
	}
	defer remoteConn.Close()

	// 2. 协议握手
	var payload []byte
	var hErr error
	isVless := false

	switch strings.ToLower(s.config.Type) {
	case "mandala":
		client := protocol.NewMandalaClient(s.config.Username, s.config.Password)
		
		// 获取随机填充大小配置
		noiseSize := 0
		if s.config.Settings != nil && s.config.Settings.Noise {
			noiseSize = s.config.Settings.NoiseSize
		}
		// 传入 noiseSize
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

	// 发送握手数据
	if len(payload) > 0 {
		if _, err := remoteConn.Write(payload); err != nil {
			r.Complete(true)
			return
		}
	}

	// VLESS 特殊处理
	if isVless {
		remoteConn = protocol.NewVlessConn(remoteConn)
	}

	// 3. 建立本地 TCP 连接端点
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		return
	}
	r.Complete(false) // 完成握手，不发送 RST

	// 转换为 Go 标准 net.Conn
	localConn := gonet.NewTCPConn(&wq, ep)
	defer localConn.Close()

	// 4. 双向转发
	go func() {
		io.Copy(localConn, remoteConn)
		localConn.CloseWrite()
	}()

	io.Copy(remoteConn, localConn)
}

// handleUDP 分发 UDP 流量：DNS 劫持或普通 UDP NAT
func (s *Stack) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	dstPort := id.LocalPort

	// 创建端点
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return
	}

	// [修复] gonet.NewUDPConn 需要传入 s.stack (类型为 *stack.Stack)
	localConn := gonet.NewUDPConn(s.stack, &wq, ep)

	// 如果是 DNS 请求 (端口 53)，进行拦截处理
	if dstPort == 53 {
		go s.handleRemoteDNS(localConn)
		return
	}

	// 其他 UDP 流量交给 NAT 管理器
	// 获取目标地址
	targetIP := id.LocalAddress.String()
	targetPort := int(dstPort)
	key := fmt.Sprintf("%s:%d", targetIP, targetPort)

	// [修复] 使用新变量 errNat，避免与 tcpip.Error 类型的 err 冲突
	session, errNat := s.nat.GetOrCreate(key, localConn, targetIP, targetPort)
	if errNat != nil {
		localConn.Close()
		return
	}

	// 将本地 UDP 数据转发给远程代理
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

// handleRemoteDNS 通过代理远程解析 DNS
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
		return
	}
	defer proxyConn.Close()

	// 2. 发送握手 (目标为 8.8.8.8:53)
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

	// 3. 封装 DNS 请求 (UDP over TCP 需要长度前缀)
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

	// 写回本地 UDP 连接
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
