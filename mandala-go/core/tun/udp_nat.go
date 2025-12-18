package tun

import (
	"log" // [修改] 使用 log 替代 fmt
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

		if session.LocalConn != localConn {
			log.Printf("[NAT] Session stale for %s, recreating...", key)
			session.RemoteConn.Close()
			m.sessions.Delete(key)
			// 继续创建新会话
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

	log.Printf("[NAT] New UDP Session: %s", key)
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
			// log.Printf("[NAT] Remote read error/timeout: %v", err)
			return
		}

		s.LastActive = time.Now()
		
		if _, err := s.LocalConn.Write(buf[:n]); err != nil {
			log.Printf("[NAT] Write to Local Stack failed: %v", err)
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
				// log.Printf("[NAT] Session timeout: %s", key)
				session.RemoteConn.Close()
				m.sessions.Delete(key)
			}
			return true
		})
	}
}
