package tun

import (
	"fmt"
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
	// [同步增强] 用于通知初始化完成情况
	ready   chan struct{} 
	initErr error         
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
	// 构造新 Session 占位符
	newSession := &UDPSession{
		LocalConn:  localConn,
		LastActive: time.Now(),
		ready:      make(chan struct{}),
	}

	// 使用 LoadOrStore 原子操作确保只有一个协程负责拨号
	actual, loaded := m.sessions.LoadOrStore(key, newSession)

	if loaded {
		existing := actual.(*UDPSession)
		
		// 等待负责拨号的协程（Leader）完成初始化
		select {
		case <-existing.ready:
			// 初始化已结束
		case <-time.After(5 * time.Second):
			return nil, fmt.Errorf("udp session init timeout")
		}

		// 检查 Leader 的初始化结果
		if existing.initErr != nil {
			return nil, existing.initErr
		}

		// 检查 LocalConn 是否变更（防止 stale session）
		if existing.LocalConn != localConn {
			log.Printf("GoLog: [NAT] 会话失效，正在清理旧连接: %s", key)
			if existing.RemoteConn != nil {
				existing.RemoteConn.Close()
			}
			m.sessions.Delete(key)
			return nil, fmt.Errorf("session stale")
		}

		existing.LastActive = time.Now()
		return existing, nil
	}

	// --- Leader 协程逻辑：负责执行拨号和协议握手 ---
	
	// 无论成功还是失败，完成后必须关闭 ready 通道以唤醒等待者
	fail := func(err error) (*UDPSession, error) {
		newSession.initErr = err
		close(newSession.ready)
		m.sessions.Delete(key) 
		return nil, err
	}

	remoteConn, err := m.dialer.Dial()
	if err != nil {
		return fail(err)
	}

	var payload []byte
	var hErr error
	isVless := false

	// 根据配置类型执行不同的握手逻辑
	switch strings.ToLower(m.config.Type) {
	case "mandala":
		client := protocol.NewMandalaClient(m.config.Username, m.config.Password)
		payload, hErr = client.BuildHandshakePayload(targetIP, targetPort, m.config.Settings.Noise)
	case "trojan":
		payload, hErr = protocol.BuildTrojanPayload(m.config.Password, targetIP, targetPort)
	case "vless":
		payload, hErr = protocol.BuildVlessPayload(m.config.UUID, targetIP, targetPort)
		isVless = true
	case "shadowsocks":
		payload, hErr = protocol.BuildShadowsocksPayload(targetIP, targetPort)
	case "socks", "socks5":
		hErr = protocol.HandshakeSocks5(remoteConn, m.config.Username, m.config.Password, targetIP, targetPort)
	}

	if hErr != nil {
		remoteConn.Close()
		return fail(hErr)
	}

	// 发送握手 Payload
	if len(payload) > 0 {
		if _, err := remoteConn.Write(payload); err != nil {
			remoteConn.Close()
			return fail(err)
		}
	}

	// 协议包装（针对 VLESS 剥离头部）
	if isVless {
		remoteConn = protocol.NewVlessConn(remoteConn)
	}

	// 初始化成功，赋值并广播状态
	newSession.RemoteConn = remoteConn
	close(newSession.ready) 
	
	// 启动后台协程将远程数据写回 Android TUN
	go m.copyRemoteToLocal(key, newSession)
	log.Printf("GoLog: [NAT] 成功创建 UDP 会话: %s", key)
	return newSession, nil
}

func (m *UDPNatManager) copyRemoteToLocal(key string, s *UDPSession) {
	defer func() {
		if s.RemoteConn != nil {
			s.RemoteConn.Close()
		}
		m.sessions.Delete(key)
	}()
	
	buf := make([]byte, 4096)
	for {
		if s.RemoteConn == nil {
			return
		}
		// 设置读取超时
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
	ticker := time.NewTicker(15 * time.Second)
	for range ticker.C {
		now := time.Now()
		m.sessions.Range(func(key, value interface{}) bool {
			session := value.(*UDPSession)
			
			// 检查会话是否初始化完成
			select {
			case <-session.ready:
				// 初始化已结束，检查是否失败或超时
				if session.RemoteConn == nil || session.initErr != nil {
					m.sessions.Delete(key)
					return true
				}
				
				if now.Sub(session.LastActive) > udpTimeout {
					log.Printf("GoLog: [NAT] 会话超时清理: %s", key)
					session.RemoteConn.Close()
					m.sessions.Delete(key)
				}
			default:
				// 正在初始化中，跳过清理，防止误杀
			}
			return true
		})
	}
}
