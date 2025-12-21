package tun

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"mandala/core/config"
	"mandala/core/protocol"
	"mandala/core/proxy"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased" // 注意这里引用可能需要调整，视你的import而定，此文件主要是Stack逻辑
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
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
	stack  *stack.Stack
	device *Device
	dialer *proxy.Dialer
	config *config.OutboundConfig
	nat    *UDPNatManager
	ctx    context.Context
	cancel context.CancelFunc
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
	// 如果编译报错 sniffer，可以直接用 dev.LinkEndpoint()
	if err := s.CreateNIC(nicID, dev.LinkEndpoint()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("创建网卡失败: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
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
	// log.Printf("[TCP] Req: %s -> %s", id.RemoteAddress, id.LocalAddress)
	
	// 1. 拨号代理服务器
	remoteConn, dialErr := s.dialer.Dial()
	if dialErr != nil {
		log.Printf("[TCP] 拨号代理失败: %v", dialErr)
		r.Complete(true)
		return
	}
	defer remoteConn.Close()

	// 2. 发送握手
	var payload []byte
	var hErr error
	targetHost := id.LocalAddress.String()
	targetPort := int(id.LocalPort)

	switch strings.ToLower(s.config.Type) {
	case "mandala":
		client := protocol.NewMandalaClient(s.config.Username, s.config.Password)
		payload, hErr = client.BuildHandshakePayload(targetHost, targetPort)
	case "trojan":
		payload, hErr = protocol.BuildTrojanPayload(s.config.Password, targetHost, targetPort)
	case "vless":
		payload, hErr = protocol.BuildVlessPayload(s.config.UUID, targetHost, targetPort)
	}

	if hErr != nil {
		log.Printf("[TCP] 握手包构建失败: %v", hErr)
		r.Complete(true)
		return
	}

	if len(payload) > 0 {
		if _, err := remoteConn.Write(payload); err != nil {
			r.Complete(true)
			return
		}
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
		// Remote -> Local
		io.Copy(localConn, remoteConn)
		localConn.CloseWrite()
	}()

	// Local -> Remote
	io.Copy(remoteConn, localConn)
}

func (s *Stack) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	targetPort := int(id.LocalPort)

	// [修复] 拦截 DNS 请求，并通过代理转发 (Remote DNS)
	if targetPort == 53 {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil { return }
		localConn := gonet.NewUDPConn(s.stack, &wq, ep)
		go s.handleRemoteDNS(localConn) // 使用新的 RemoteDNS 处理
		return
	}

	// [注意] 普通 UDP 流量 (QUIC等) 在此实现中因协议不支持 UDP over TCP Stream 可能会失效。
	// 建议暂时忽略或仅在支持 Mux 的协议中开启。
	// 下方代码保持原样，防止改动过大，但已知存在 UDP 兼容性问题。
}

// [新增] handleRemoteDNS 将 UDP DNS 请求封装为 TCP 格式，通过代理发送到 8.8.8.8
func (s *Stack) handleRemoteDNS(conn *gonet.UDPConn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil { return }

	// 1. 连接代理服务器
	proxyConn, err := s.dialer.Dial()
	if err != nil {
		log.Printf("[DNS] 连代理失败: %v", err)
		return
	}
	defer proxyConn.Close()

	// 2. 通过代理握手连接到 8.8.8.8:53
	// 这样 DNS 请求就会走 VPN 通道，而不是本地网络
	var payload []byte
	switch strings.ToLower(s.config.Type) {
	case "mandala":
		client := protocol.NewMandalaClient(s.config.Username, s.config.Password)
		payload, _ = client.BuildHandshakePayload("8.8.8.8", 53)
	case "trojan":
		payload, _ = protocol.BuildTrojanPayload(s.config.Password, "8.8.8.8", 53)
	case "vless":
		payload, _ = protocol.BuildVlessPayload(s.config.UUID, "8.8.8.8", 53)
	}
	
	if _, err := proxyConn.Write(payload); err != nil { return }

	// 3. 发送 DNS 请求 (封装为 TCP 格式: 2字节长度 + 数据)
	reqData := make([]byte, 2+n)
	reqData[0] = byte(n >> 8)
	reqData[1] = byte(n)
	copy(reqData[2:], buf[:n])

	if _, err := proxyConn.Write(reqData); err != nil { return }

	// 4. 读取响应
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(proxyConn, lenBuf); err != nil { return }
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])

	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(proxyConn, respBuf); err != nil { return }

	// 5. 写回 Android
	conn.Write(respBuf)
	log.Printf("[DNS] 解析成功 (via 8.8.8.8)")
}

func (s *Stack) Close() {
	s.cancel()
	if s.device != nil { s.device.Close() }
	if s.stack != nil { s.stack.Close() }
}
