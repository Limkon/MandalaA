package tun

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"mandala/core/config"
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

// Stack 服务结构体
type Stack struct {
	stack      *stack.Stack
	device     *Device
	dialer     *proxy.Dialer
	config     *config.OutboundConfig
	ctx        context.Context
	cancel     context.CancelFunc
}

// StartStack 启动 TUN 处理栈
func StartStack(fd int, mtu int, cfg *config.OutboundConfig) (*Stack, error) {
	// 1. 创建 TUN 设备包装
	dev, err := NewDevice(fd, uint32(mtu))
	if err != nil {
		return nil, err
	}

	// 2. 初始化 gVisor 协议栈
	// 包含 IPv4, IPv6, TCP, UDP
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

	// 3. 注册 NIC (Network Interface Controller)
	nicID := tcpip.NICID(1)
	if err := s.CreateNIC(nicID, dev.LinkEndpoint()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("create nic failed: %v", err)
	}

	// 4. 添加默认路由 (Promiscuous Mode, 接收所有包)
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: tcpip.Address{}, // Default Route
			Mask:        tcpip.Address{},
			NIC:         nicID,
		},
	})

	// 5. 启用转发 (虽然我们是在用户态处理，但设置这个是个好习惯)
	s.SetPromiscuousMode(nicID, true)
	
	// 启用 TCP SACK 等优化
	s.SetTransportProtocolOption(tcp.ProtocolNumber, tcp.SACKEnabled(true))

	ctx, cancel := context.WithCancel(context.Background())
	
	tStack := &Stack{
		stack:  s,
		device: dev,
		dialer: proxy.NewDialer(cfg), // 使用现有的代理 Dialer
		config: cfg,
		ctx:    ctx,
		cancel: cancel,
	}

	// 6. 设置 Packet 处理回调 (核心转发逻辑)
	// 将 stack 接收到的 TCP/UDP 连接转发给我们的处理函数
	tStack.startPacketHandling()

	return tStack, nil
}

// Close 停止栈
func (s *Stack) Close() {
	s.cancel()
	if s.device != nil {
		s.device.Close()
	}
	if s.stack != nil {
		s.stack.Close()
	}
}

// startPacketHandling 设置流量劫持
func (s *Stack) startPacketHandling() {
	// 处理 TCP
	tcpHandler := tcp.NewForwarder(s.stack, 30000, 10, func(r *tcp.ForwarderRequest) {
		// 每次有新连接时，启动一个协程处理
		go s.handleTCP(r)
	})
	s.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpHandler.HandlePacket)

	// 处理 UDP
	udpHandler := udp.NewForwarder(s.stack, func(r *udp.ForwarderRequest) {
		go s.handleUDP(r)
	})
	s.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpHandler.HandlePacket)
}

// handleTCP 处理单个 TCP 连接
func (s *Stack) handleTCP(r *tcp.ForwarderRequest) {
	// 1. 获取目标地址
	id := r.ID()
	// 将 gVisor 的地址转换为 Go 的 net.IP
	targetIP := net.IP(id.LocalAddress.AsSlice()) // 注意：对于 ForwarderRequest，LocalAddress 是原本的目标地址
	targetPort := id.LocalPort
	targetAddr := fmt.Sprintf("%s:%d", targetIP.String(), targetPort)

	// 2. 建立 gVisor 侧的连接端点 (gonet.Conn)
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true) // 发送 RST
		return
	}
	r.Complete(false) // 完成握手

	// 将 Endpoint 包装为 net.Conn
	localConn := gonet.NewTCPConn(&wq, ep)
	defer localConn.Close()

	fmt.Printf("[TUN] TCP Connect to %s\n", targetAddr)

	// 3. 连接代理服务器
	// 这里我们需要复用之前的 HandleConnection 逻辑，或者直接 Dial
	// 因为我们是直接转发流量，所以不需要 SOCKS5 握手，直接让 Dialer 连上并转发即可
	// 但 Dialer.Dial() 返回的是连上代理服务器的连接，我们需要在那之上建立具体的协议隧道
	
	// 这里有一个关键点：
	// 如果是 "mandala" 协议，我们需要像 HandleConnection 步骤4那样，先发握手包
	
	remoteConn, err := s.dialer.Dial()
	if err != nil {
		fmt.Printf("[TUN] Dial proxy failed: %v\n", err)
		return
	}
	defer remoteConn.Close()

	// 4. 发送 Mandala 协议握手 (参考 handler.go)
	// TODO: 这里代码有重复，未来应该把握手逻辑封装到 Dialer 或 Protocol Client 中
	if s.config.Type == "mandala" {
		client := proxy.NewMandalaClient(s.config.Username, s.config.Password)
		payload, err := client.BuildHandshakePayload(targetIP.String(), int(targetPort))
		if err != nil {
			return
		}
		if _, err := remoteConn.Write(payload); err != nil {
			return
		}
	}

	// 5. 双向转发
	go io.Copy(remoteConn, localConn)
	io.Copy(localConn, remoteConn)
}

// handleUDP 处理 UDP (简化版，每个包都可能触发，生产环境需要 NAT 表)
func (s *Stack) handleUDP(r *udp.ForwarderRequest) {
	// 简单实现：读取这个 UDP 包，转发，然后丢弃
	// 完整的 UDP 需要 Session 管理，这里先暂时建立一个短连接
	
	id := r.ID()
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return
	}
	
	localConn := gonet.NewUDPConn(s.stack, &wq, ep)
	defer localConn.Close()

	// 读取数据
	buf := make([]byte, 65535)
	n, err := localConn.Read(buf)
	if err != nil {
		return
	}

	// 目前示例代码仅处理 TCP，UDP 的完整实现较为复杂（需要维护会话映射），
	// 这里为了保证代码通过编译且不报错，暂时只打印日志。
	// 实际项目中需要实现 UDP NAT Map。
	fmt.Printf("[TUN] UDP Packet %d bytes (Not fully implemented)\n", n)
}
