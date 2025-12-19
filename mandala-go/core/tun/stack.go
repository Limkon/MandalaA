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
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func init() {
	// 统一日志前缀，方便 Logcat 过滤 "GoLog"
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

	// 开启 IP 转发
	s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true)
	s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true)

	nicID := tcpip.NICID(1)
	// 使用 Sniffer 包装 endpoint，方便内部调试，也可以直接用 dev.LinkEndpoint()
	if err := s.CreateNIC(nicID, sniffer.New(dev.LinkEndpoint())); err != nil {
		dev.Close()
		return nil, fmt.Errorf("创建网卡失败: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	// 设置混杂模式，确保能接收所有包
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
	// TCP 处理程序
	tcpHandler := tcp.NewForwarder(s.stack, 30000, 10, func(r *tcp.ForwarderRequest) {
		go s.handleTCP(r)
	})
	s.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpHandler.HandlePacket)

	// UDP 处理程序
	udpHandler := udp.NewForwarder(s.stack, func(r *udp.ForwarderRequest) {
		s.handleUDP(r)
	})
	s.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpHandler.HandlePacket)
}

func (s *Stack) handleTCP(r *tcp.ForwarderRequest) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[TCP] Panic recovered: %v", err)
		}
	}()

	id := r.ID()
	// 如果需要极详细的日志，可以解开下面这行，但会刷屏
	// log.Printf("[TCP] New Req: %s:%d -> %s:%d", id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort)
	
	// 1. 尝试拨号远程代理服务器
	remoteConn, dialErr := s.dialer.Dial()
	if dialErr != nil {
		log.Printf("[TCP] Dial remote failed (%s): %v", id.LocalAddress, dialErr)
		r.Complete(true) // 发送 RST 拒绝连接
		return
	}
	defer remoteConn.Close()

	// 2. 构造协议握手包
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
		log.Printf("[TCP] Handshake build failed: %v", hErr)
		r.Complete(true)
		return
	}

	// 发送握手包
	if len(payload) > 0 {
		if _, err := remoteConn.Write(payload); err != nil {
			log.Printf("[TCP] Handshake send failed: %v", err)
			r.Complete(true)
			return
		}
	}

	// 3. 接受本地连接 (gVisor -> App)
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		log.Printf("[TCP] CreateEndpoint failed: %v", err)
		r.Complete(true)
		return
	}
	r.Complete(false) // false 表示我们要处理这个连接，不要 RST

	localConn := gonet.NewTCPConn(&wq, ep)
	defer localConn.Close()

	// 4. 双向数据转发与诊断
	// log.Printf("[TCP] Tunnel established: %s:%d", targetHost, targetPort)

	// 使用 channel 监控 Rx 方向是否完成
	rxDone := make(chan struct{})

	// --- 方向 A: Remote (代理) -> Local (手机 App) [Rx] ---
	go func() {
		defer close(rxDone)
		// 从远程读取，写入本地
		n, err := io.Copy(localConn, remoteConn)
		
		if n > 0 {
			// [关键诊断点]
			// 如果这里打印了 > 0 的字节，说明代理服务器正常回传了数据。
			// 如果此时手机上显示网速为 0，则必定是 TUN 接口 Checksum 问题。
			log.Printf("[TCP] Rx (Remote->App) Success: %d bytes. (Err: %v)", n, err)
		} else {
			// 如果这里是 0，说明连接刚建立就被关闭，或者代理服务器没有发送任何数据就断开了。
			log.Printf("[TCP] Rx (Remote->App) Zero bytes! Proxy no response. (Err: %v)", err)
		}
		// 关闭本地连接的写入端，这会向 App 发送 FIN
		localConn.CloseWrite()
	}()

	// --- 方向 B: Local (手机 App) -> Remote (代理) [Tx] ---
	go func() {
		// 从本地读取，写入远程
		n, err := io.Copy(remoteConn, localConn)
		if err != nil && err != io.EOF {
			log.Printf("[TCP] Tx (App->Remote) Error: %v (Sent: %d)", err, n)
		}
		// 关闭远程连接的读取端，这会强制中断 Rx 协程中的 Read 操作
		remoteConn.SetReadDeadline(time.Now())
	}()

	// 等待 Rx 结束才退出 handleTCP，确保资源不提前释放
	<-rxDone
}

func (s *Stack) handleUDP(r *udp.ForwarderRequest) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[UDP] Panic recovered: %v", err)
		}
	}()

	id := r.ID()
	targetPort := int(id.LocalPort)
    
	// 拦截 DNS 请求
	if targetPort == 53 {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil { return }
		localConn := gonet.NewUDPConn(s.stack, &wq, ep)
		go s.handleLocalDNS(localConn)
		return
	}

	targetIP := net.IP(id.LocalAddress.AsSlice()).String()
	// 构造 NAT Key
	srcKey := fmt.Sprintf("%s:%d->%s:%d", id.RemoteAddress.String(), id.RemotePort, targetIP, targetPort)

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil { return }

	localConn := gonet.NewUDPConn(s.stack, &wq, ep)
	
	// 获取或创建 NAT 会话
	session, natErr := s.nat.GetOrCreate(srcKey, localConn, targetIP, targetPort)
	if natErr != nil {
		log.Printf("[UDP] NAT create failed: %v", natErr)
		localConn.Close()
		return
	}

	// 启动单向转发 (Local -> Remote)
	// Remote -> Local 的转发由 NAT Manager 负责
	go func() {
		defer localConn.Close()
		buf := make([]byte, 4096)
		for {
			// 设置读取超时，防止协程泄漏
			localConn.SetDeadline(time.Now().Add(60 * time.Second))
			n, rErr := localConn.Read(buf)
			if rErr != nil { return }
			if _, wErr := session.RemoteConn.Write(buf[:n]); wErr != nil { return }
		}
	}()
}

func (s *Stack) handleLocalDNS(conn *gonet.UDPConn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil { return }

	// 这里硬编码了阿里 DNS (TCP)，实际可改为配置项
	realDNS := "223.5.5.5:53"
	tcpConn, err := net.DialTimeout("tcp", realDNS, 3*time.Second)
	if err != nil {
		log.Printf("[DNS] Dial failed: %v", err)
		return 
	}
	defer tcpConn.Close()

	// 封装 DNS over TCP 请求 (2字节长度头)
	reqData := make([]byte, 2+n)
	reqData[0] = byte(n >> 8)
	reqData[1] = byte(n)
	copy(reqData[2:], buf[:n])

	if _, err := tcpConn.Write(reqData); err != nil { return }

	// 读取响应长度
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, lenBuf); err != nil { return }
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])

	// 读取响应体
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(tcpConn, respBuf); err != nil { return }
	
	// 写回 UDP 给 Android
	conn.Write(respBuf)
}

func (s *Stack) Close() {
	log.Println("[Stack] Stopping and cleaning up...")
	s.cancel()
	if s.device != nil { s.device.Close() }
	if s.stack != nil { s.stack.Close() }
}
