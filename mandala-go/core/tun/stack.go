package tun

import (
	"context"
	"fmt"
	"io"
	"net"

	"mandala/core/config"
	"mandala/core/protocol" // 必须引用，用于 TCP 握手
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

// Stack 负责管理 gVisor 网络栈和流量转发
type Stack struct {
	stack  *stack.Stack
	device *Device
	dialer *proxy.Dialer
	config *config.OutboundConfig
	nat    *UDPNatManager // UDP 会话管理器
	ctx    context.Context
	cancel context.CancelFunc
}

// StartStack 初始化并启动 gVisor 网络栈
// fd: Android VpnService 提供的文件描述符
// mtu: 最大传输单元
// cfg: 节点配置
func StartStack(fd int, mtu int, cfg *config.OutboundConfig) (*Stack, error) {
	// 1. 创建 TUN 设备包装器 (见 device.go)
	dev, err := NewDevice(fd, uint32(mtu))
	if err != nil {
		return nil, err
	}

	// 2. 初始化 gVisor 协议栈 (支持 IPv4/IPv6, TCP/UDP)
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

	// 3. 创建并注册 NIC (网络接口控制器)
	nicID := tcpip.NICID(1)
	if err := s.CreateNIC(nicID, dev.LinkEndpoint()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("create nic failed: %v", err)
	}

	// 4. 设置路由表 (Promiscuous Mode, 接收所有流量)
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: tcpip.Address{}, // 默认路由
			Mask:        tcpip.Address{},
			NIC:         nicID,
		},
	})

	// 允许接收发往任何 IP 的包
	s.SetPromiscuousMode(nicID, true)
	
	// 启用 TCP SACK (选择性确认) 以提高性能
	s.SetTransportProtocolOption(tcp.ProtocolNumber, tcp.SACKEnabled(true))

	ctx, cancel := context.WithCancel(context.Background())
	
	dialer := proxy.NewDialer(cfg)

	tStack := &Stack{
		stack:  s,
		device: dev,
		dialer: dialer,
		config: cfg,
		nat:    NewUDPNatManager(dialer, cfg), // 初始化 UDP NAT 管理器
		ctx:    ctx,
		cancel: cancel,
	}

	// 5. 开始拦截并处理数据包
	tStack.startPacketHandling()

	return tStack, nil
}

// Close 停止网络栈并释放资源
func (s *Stack) Close() {
	s.cancel()
	if s.device != nil {
		s.device.Close()
	}
	if s.stack != nil {
		s.stack.Close()
	}
}

// startPacketHandling 配置 TCP 和 UDP 的转发处理函数
func (s *Stack) startPacketHandling() {
	// --- TCP 处理 ---
	// SetForwarder 拦截所有进入 Stack 的 TCP 连接
	tcpHandler := tcp.NewForwarder(s.stack, 30000, 10, func(r *tcp.ForwarderRequest) {
		// 为每个新连接启动一个协程
		go s.handleTCP(r)
	})
	s.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpHandler.HandlePacket)

	// --- UDP 处理 ---
	// 拦截所有 UDP 数据包
	udpHandler := udp.NewForwarder(s.stack, func(r *udp.ForwarderRequest) {
		// 注意：UDP 是无连接的，这里每次收到包都会触发，需在内部通过 NAT Map 去重/复用
		s.handleUDP(r)
	})
	s.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpHandler.HandlePacket)
}

// handleTCP 处理单个 TCP 连接
func (s *Stack) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	// 获取目标地址 (注意: LocalAddress 在这里是指数据包要去的目标)
	targetIP := net.IP(id.LocalAddress.AsSlice())
	targetPort := id.LocalPort
	
	// 1. 创建 gVisor 侧的端点 (与 App 通信)
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true) // 发送 RST 拒绝连接
		return
	}
	r.Complete(false) // 完成握手

	// 包装成标准的 net.Conn
	localConn := gonet.NewTCPConn(&wq, ep)
	defer localConn.Close()
	
	fmt.Printf("[TCP] Connect to %s:%d\n", targetIP, targetPort)

	// 2. 连接代理服务器
	remoteConn, err := s.dialer.Dial()
	if err != nil {
		fmt.Printf("[TCP] Dial failed: %v\n", err)
		return
	}
	defer remoteConn.Close()

	// 3. 发送协议握手 (针对 Mandala 协议)
	if s.config.Type == "mandala" {
		client := protocol.NewMandalaClient(s.config.Username, s.config.Password)
		payload, err := client.BuildHandshakePayload(targetIP.String(), int(targetPort))
		if err != nil {
			fmt.Printf("[TCP] Handshake build failed: %v\n", err)
			return 
		}
		if _, err := remoteConn.Write(payload); err != nil {
			fmt.Printf("[TCP] Handshake send failed: %v\n", err)
			return
		}
	}

	// 4. 双向数据转发
	go io.Copy(remoteConn, localConn) // App -> Proxy
	io.Copy(localConn, remoteConn)    // Proxy -> App
}

// handleUDP 处理 UDP 数据包 (接入 NAT 管理器)
func (s *Stack) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	
	// 1. 获取目标信息
	targetIP := net.IP(id.LocalAddress.AsSlice()).String()
	targetPort := int(id.LocalPort)
	
	// 2. 生成会话 Key: "SrcIP:SrcPort -> DstIP:DstPort"
	// 这样可以区分同一个 App 发往不同服务器的请求，或者不同 App 的请求
	srcKey := fmt.Sprintf("%s:%d->%s:%d", 
		id.RemoteAddress.String(), id.RemotePort,
		targetIP, targetPort)

	// 3. 创建 gVisor 端点 (用于读取当前数据包)
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return
	}
	localConn := gonet.NewUDPConn(s.stack, &wq, ep)

	// 4. 通过 NAT 管理器获取会话 (复用连接 或 新建连接)
	// 如果是新连接，GetOrCreate 内部会负责连接代理服务器并完成握手
	session, err := s.nat.GetOrCreate(srcKey, localConn, targetIP, targetPort)
	if err != nil {
		localConn.Close()
		fmt.Printf("[UDP] Session create failed: %v\n", err)
		return
	}

	// 5. 转发当前数据包 (App -> Proxy)
	// 启动一个协程读取 localConn 的数据并发给 session.remoteConn
	go func() {
		defer localConn.Close() // 处理完当前包后关闭这个临时的 localConn

		buf := make([]byte, 4096)
		n, err := localConn.Read(buf)
		if err != nil {
			return 
		}

		// 将数据写入代理连接
		// 只要 Session 里的 remoteConn 没断，代理服务器就能收到
		_, err = session.remoteConn.Write(buf[:n])
		if err != nil {
			// 如果写失败，可能是远程连接断了，NAT 管理器稍后会清理
			return
		}
		
		// 更新最后活跃时间
		session.lastActive = config.NowFunc() // 或 time.Now()，视 config 实现而定
	}()
	
	// 注意: 下行数据 (Proxy -> App) 的转发是由 NAT 管理器在 GetOrCreate 时启动的协程负责的
	// 那里持有了 localConn 的引用用于回写
}
