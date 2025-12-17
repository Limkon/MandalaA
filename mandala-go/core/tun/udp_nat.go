package tun

import (
	"fmt"
	"net"
	"sync"
	"time"

	"mandala/core/config"
	"mandala/core/protocol"
	"mandala/core/proxy"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

const (
	udpTimeout = 60 * time.Second
)

type UDPSession struct {
	LocalConn  *gonet.UDPConn
	RemoteConn net.Conn
	LastActive time.Time
}

type UDPNatManager struct {
	sessions sync.Map
	dialer   *proxy.Dialer
	config   *config.OutboundConfig
}

func NewUDPNatManager(dialer *proxy.Dialer, cfg *config.OutboundConfig) *UDPNatManager {
	m := &UDPNatManager{
		dialer: dialer,
		config: cfg,
	}
	go m.cleanupLoop()
	return m
}

func (m *UDPNatManager) GetOrCreate(key string, localConn *gonet.UDPConn, targetIP string, targetPort int) (*UDPSession, error) {
	if val, ok := m.sessions.Load(key); ok {
		session := val.(*UDPSession)

		// [关键修复] 检查 gVisor 的本地连接句柄是否发生了变化
		// 如果 localConn 不相等，说明旧的 endpoint 已经销毁，旧的 session.LocalConn 指向了无效资源。
		// 此时旧的 copyRemoteToLocal 协程可能已经退出或正在报错。
		// 最安全的做法是：关闭旧的远程连接，强制重新建立会话。
		if session.LocalConn != localConn {
			// fmt.Printf("[NAT] Session stale for %s, recreating...\n", key)
			session.RemoteConn.Close()
			m.sessions.Delete(key)
			// 继续向下执行，创建新会话
		} else {
			session.LastActive = time.Now()
			return session, nil
		}
	}

	remoteConn, err := m.dialer.Dial()
	if err != nil {
		return nil, err
	}

	// [协议适配] 发送 UDP 握手包
	// 目前仅演示 Mandala 协议，VLESS/Trojan UDP 需要封装 Packet，后续请补充
	if m.config.Type == "mandala" {
		client := protocol.NewMandalaClient(m.config.Username, m.config.Password)
		payload, err := client.BuildHandshakePayload(targetIP, targetPort)
		if err != nil {
			remoteConn.Close()
			return nil, err
		}
		if _, err := remoteConn.Write(payload); err != nil {
			remoteConn.Close()
			return nil, err
		}
	}

	session := &UDPSession{
		LocalConn:  localConn,
		RemoteConn: remoteConn,
		LastActive: time.Now(),
	}

	m.sessions.Store(key, session)
	go m.copyRemoteToLocal(key, session)

	fmt.Printf("[NAT] New UDP Session: %s\n", key)
	return session, nil
}

func (m *UDPNatManager) copyRemoteToLocal(key string, s *UDPSession) {
	defer func() {
		s.RemoteConn.Close()
		m.sessions.Delete(key)
	}()

	buf := make([]byte, 4096)
	for {
		s.RemoteConn.SetReadDeadline(time.Now().Add(udpTimeout))
		n, err := s.RemoteConn.Read(buf)
		if err != nil {
			return
		}

		s.LastActive = time.Now()
		// 如果 s.LocalConn 已经失效（例如 gVisor 关闭了 endpoint），这里会报错并退出
		if _, err := s.LocalConn.Write(buf[:n]); err != nil {
			return
		}
	}
}

func (m *UDPNatManager) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		now := time.Now()
		m.sessions.Range(func(key, value interface{}) bool {
			session := value.(*UDPSession)
			if now.Sub(session.LastActive) > udpTimeout {
				session.RemoteConn.Close()
				m.sessions.Delete(key)
			}
			return true
		})
	}
}
