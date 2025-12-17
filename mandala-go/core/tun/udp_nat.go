package tun

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"mandala/core/config"
	"mandala/core/protocol"
	"mandala/core/proxy"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

const (
	udpTimeout = 60 * time.Second // 会话超时时间
)

// UDPSession 代表一个活跃的 UDP 流
type UDPSession struct {
	localConn  *gonet.UDPConn // 连接到 Android/Tun 的管道
	remoteConn net.Conn       // 连接到 Proxy 的管道
	lastActive time.Time      // 最后活跃时间
}

// UDPNatManager 管理所有 UDP 会话
type UDPNatManager struct {
	sessions sync.Map // map[string]*UDPSession
	dialer   *proxy.Dialer
	config   *config.OutboundConfig
}

func NewUDPNatManager(dialer *proxy.Dialer, cfg *config.OutboundConfig) *UDPNatManager {
	m := &UDPNatManager{
		dialer: dialer,
		config: cfg,
	}
	// 启动清理协程
	go m.cleanupLoop()
	return m
}

// GetOrCreate 获取现有会话或创建新会话
func (m *UDPNatManager) GetOrCreate(key string, localConn *gonet.UDPConn, targetIP string, targetPort int) (*UDPSession, error) {
	// 1. 尝试从缓存获取
	if val, ok := m.sessions.Load(key); ok {
		session := val.(*UDPSession)
		session.lastActive = time.Now()
		return session, nil
	}

	// 2. 创建新连接到代理服务器
	remoteConn, err := m.dialer.Dial()
	if err != nil {
		return nil, err
	}

	// 3. 如果是 Mandala 协议，需要发送握手
	// 注意：UDP over TCP/Stream 模式下，通常每个 Session 都要握手
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
		localConn:  localConn,
		remoteConn: remoteConn,
		lastActive: time.Now(),
	}

	// 4. 保存到 Map
	m.sessions.Store(key, session)

	// 5. 启动下行数据转发 (Proxy -> App)
	go m.copyRemoteToLocal(key, session)

	fmt.Printf("[NAT] New UDP Session: %s\n", key)
	return session, nil
}

// copyRemoteToLocal 从代理读取数据并写回 Tun (下行)
func (m *UDPNatManager) copyRemoteToLocal(key string, s *UDPSession) {
	defer func() {
		s.remoteConn.Close()
		m.sessions.Delete(key) // 结束时移除会话
	}()

	buf := make([]byte, 4096)
	for {
		// 设置读取超时，触发心跳检测
		s.remoteConn.SetReadDeadline(time.Now().Add(udpTimeout))
		n, err := s.remoteConn.Read(buf)
		if err != nil {
			return
		}
		
		s.lastActive = time.Now()
		
		// 写回给 Android (gVisor)
		if _, err := s.localConn.Write(buf[:n]); err != nil {
			return
		}
	}
}

// cleanupLoop 定期清理过期会话
func (m *UDPNatManager) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		now := time.Now()
		m.sessions.Range(func(key, value interface{}) bool {
			session := value.(*UDPSession)
			if now.Sub(session.lastActive) > udpTimeout {
				session.remoteConn.Close()
				m.sessions.Delete(key)
				// fmt.Printf("[NAT] Session timeout: %v\n", key)
			}
			return true
		})
	}
}
