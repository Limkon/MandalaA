// 文件路径: mandala-go/core/tun/stack.go

package tun

import (
	"context"
	"fmt"
	"io"
	"net"
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
	// [验证标记] 请在 Logcat 搜索 "MANDALA_DEBUG" 确认这行日志存在
	fmt.Println("MANDALA_DEBUG: Core Version 2025-TCP-DNS-Fix-v2 Starting...")

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

	nicID := tcpip.NICID(1)
	if err := s.CreateNIC(nicID, dev.LinkEndpoint()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("create nic failed: %v", err)
	}

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
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("MANDALA_DEBUG: TCP Panic recovered: %v\n", r)
		}
	}()

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

	// 打印 TCP 连接尝试
	// fmt.Printf("MANDALA_DEBUG: TCP Connect %s:%d\n", targetIP, targetPort)

	remoteConn, dialErr := s.dialer.Dial()
	if dialErr != nil {
		fmt.Printf("MANDALA_DEBUG: Proxy Dial Failed: %v\n", dialErr)
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
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("MANDALA_DEBUG: UDP Panic recovered: %v\n", r)
		}
	}()

	id := r.ID()
	targetPort := int(id.LocalPort)

	// [拦截 DNS]
	if targetPort == 53 {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return
		}
		localConn := gonet.NewUDPConn(s.stack, &wq, ep)
		go s.handleLocalDNS(localConn)
		return
	}

	targetIP := net.IP(id.LocalAddress.AsSlice()).String()
	srcKey := fmt.Sprintf("%s:%d->%s:%d",
		id.RemoteAddress.String(), id.RemotePort,
		targetIP, targetPort)

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

// [增强版] 使用 TCP 协议请求国内 DNS
// 更加稳定，穿透性更好，解决 UDP 丢包问题
func (s *Stack) handleLocalDNS(conn *gonet.UDPConn) {
	defer conn.Close()
	
	// 读取 Android 发来的 DNS 请求 (UDP)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	// 打印日志，确认 DNS 请求到了这里
	// fmt.Println("MANDALA_DEBUG: DNS Request Intercepted, forwarding via TCP...")

	// 使用 TCP 连接阿里 DNS (223.5.5.5:53)
	// TCP DNS 在网络环境恶劣时比 UDP 更可靠
	realDNS := "223.5.5.5:53"
	
	tcpConn, err := net.DialTimeout("tcp", realDNS, 3*time.Second)
	if err != nil {
		fmt.Printf("MANDALA_DEBUG: DNS Dial TCP failed: %v\n", err)
		return
	}
	defer tcpConn.Close()

	// DNS over TCP 需要在包头增加 2 字节长度
	// 格式: [Length(2)][DNS Payload]
	reqData := make([]byte, 2+n)
	reqData[0] = byte(n >> 8)
	reqData[1] = byte(n)
	copy(reqData[2:], buf[:n])

	if _, err := tcpConn.Write(reqData); err != nil {
		fmt.Printf("MANDALA_DEBUG: DNS Write TCP failed: %v\n", err)
		return
	}

	// 读取响应
	tcpConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	
	// 先读 2 字节长度
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, lenBuf); err != nil {
		fmt.Printf("MANDALA_DEBUG: DNS Read Len failed: %v\n", err)
		return
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])

	// 再读 Payload
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(tcpConn, respBuf); err != nil {
		fmt.Printf("MANDALA_DEBUG: DNS Read Payload failed: %v\n", err)
		return
	}

	// 成功获取 IP，写回给 VPN (UDP)
	// fmt.Printf("MANDALA_DEBUG: DNS Resolved! Length: %d\n", respLen)
	conn.Write(respBuf)
}
