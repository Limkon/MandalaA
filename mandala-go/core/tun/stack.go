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
	log.SetPrefix("GoLog: ")
	log.SetFlags(log.Ltime | log.Lshortfile)
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

// StartStack 初始化 gVisor 網絡棧並配置路由
func StartStack(fd int, mtu int, cfg *config.OutboundConfig) (*Stack, error) {
	log.Printf("=== Go Core Starting (FD: %d, MTU: %d) ===", fd, mtu)

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
	rawEndpoint := dev.LinkEndpoint()
	sniffedEndpoint := sniffer.New(rawEndpoint)

	if err := s.CreateNIC(nicID, sniffedEndpoint); err != nil {
		dev.Close()
		return nil, fmt.Errorf("create nic failed: %v", err)
	}

	// 核心修復：同時設置 IPv4 和 IPv6 默認路由，防止流量泄露
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
		if err := recover(); err != nil {
			log.Printf("TCP Panic Recovery: %v", err)
		}
	}()

	id := r.ID()
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		return
	}

	// 連接到遠端代理伺服器
	remoteConn, dialErr := s.dialer.Dial()
	if dialErr != nil {
		log.Printf("TCP Dial Failed (%s:%d): %v", id.LocalAddress, id.LocalPort, dialErr)
		r.Complete(true)
		ep.Close()
		return
	}
	defer remoteConn.Close()

	// 協議握手邏輯
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
	default:
		log.Printf("Warning: Unsupported protocol type %s, trying direct pass", s.config.Type)
	}

	if hErr != nil {
		log.Printf("Handshake Generation Error: %v", hErr)
		r.Complete(true)
		return
	}

	if len(payload) > 0 {
		if _, wErr := remoteConn.Write(payload); wErr != nil {
			log.Printf("Handshake Write Error: %v", wErr)
			r.Complete(true)
			return
		}
	}

	// 接受連接
	r.Complete(false)
	localConn := gonet.NewTCPConn(&wq, ep)
	defer localConn.Close()

	// 雙向數據轉發
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(remoteConn, localConn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(localConn, remoteConn)
		errChan <- err
	}()

	<-errChan
}

func (s *Stack) handleUDP(r *udp.ForwarderRequest) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("UDP Panic Recovery: %v", err)
		}
	}()

	id := r.ID()
	targetPort := int(id.LocalPort)
    
	// 劫持 53 端口流量進行加密 DNS 查詢
	if targetPort == 53 {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil { return }
		localConn := gonet.NewUDPConn(s.stack, &wq, ep)
		go s.handleLocalDNS(localConn)
		return
	}

	targetIP := net.IP(id.LocalAddress.AsSlice()).String()
	srcKey := fmt.Sprintf("%s:%d->%s:%d", id.RemoteAddress.String(), id.RemotePort, targetIP, targetPort)

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil { return }

	localConn := gonet.NewUDPConn(s.stack, &wq, ep)
	session, natErr := s.nat.GetOrCreate(srcKey, localConn, targetIP, targetPort)
	if natErr != nil {
		log.Printf("UDP NAT Session Create Failed: %v", natErr)
		localConn.Close()
		return
	}

	go func() {
		defer localConn.Close()
		buf := make([]byte, 4096)
		for {
			localConn.SetDeadline(time.Now().Add(60 * time.Second))
			n, rErr := localConn.Read(buf)
			if rErr != nil { return }
			if _, wErr := session.RemoteConn.Write(buf[:n]); wErr != nil { return }
		}
	}()
}

// handleLocalDNS 實現 UDP-to-TCP 的 DNS 轉發，解決 UDP 53 被屏蔽問題
func (s *Stack) handleLocalDNS(conn *gonet.UDPConn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil { return }

	// 使用公共 DNS (可配置)
	realDNS := "223.5.5.5:53"
	tcpConn, err := net.DialTimeout("tcp", realDNS, 3*time.Second)
	if err != nil {
		log.Printf("DNS TCP Dial Failed: %v", err)
		return
	}
	defer tcpConn.Close()

	// 構造 DNS-over-TCP 請求 (RFC 1035: 2字節長度前綴 + 原數據)
	reqData := make([]byte, 2+n)
	reqData[0] = byte(n >> 8)
	reqData[1] = byte(n)
	copy(reqData[2:], buf[:n])

	if _, err := tcpConn.Write(reqData); err != nil { return }

	// 讀取響應
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, lenBuf); err != nil { return }
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])

	if respLen > 1500 { // 異常包過濾
		return
	}

	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(tcpConn, respBuf); err != nil { return }
	conn.Write(respBuf)
}

func (s *Stack) Close() {
	s.cancel()
	if s.device != nil { s.device.Close() }
	if s.stack != nil { s.stack.Close() }
	log.Println("Go Core Stack Closed")
}
