package tun

import (
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"mandala/core/config"
	"mandala/core/protocol"
	"mandala/core/proxy"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

const udpTimeout = 60 * time.Second

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
			log.Printf("GoLog: [NAT] Session stale for %s", key)
			session.RemoteConn.Close()
			m.sessions.Delete(key)
		} else {
			session.LastActive = time.Now()
			return session, nil
		}
	}

	remoteConn, err := m.dialer.Dial()
	if err != nil {
		return nil, err
	}

	var payload []byte
	var hErr error
	isVless := false

	switch strings.ToLower(m.config.Type) {
	case "mandala":
		client := protocol.NewMandalaClient(m.config.Username, m.config.Password)
		payload, hErr = client.BuildHandshakePayload(targetIP, targetPort)
	case "trojan":
		payload, hErr = protocol.BuildTrojanPayload(m.config.Password, targetIP, targetPort)
	case "vless":
		payload, hErr = protocol.BuildVlessPayload(m.config.UUID, targetIP, targetPort)
		isVless = true
	}

	if hErr != nil {
		remoteConn.Close()
		return nil, hErr
	}

	if len(payload) > 0 {
		if _, err := remoteConn.Write(payload); err != nil {
			remoteConn.Close()
			return nil, err
		}
	}

	// [新增] 如果是 VLESS，包装连接以剥离响应头
	if isVless {
		remoteConn = protocol.NewVlessConn(remoteConn)
	}

	session := &UDPSession{
		LocalConn:  localConn,
		RemoteConn: remoteConn,
		LastActive: time.Now(),
	}

	m.sessions.Store(key, session)
	go m.copyRemoteToLocal(key, session)
	log.Printf("GoLog: [NAT] Created UDP session for %s", key)
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
