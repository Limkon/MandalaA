package proxy

import (
	"io"
	"log"
	"net"
	"strings"
	"syscall"
	"time"

	"mandala/core/config"
	"mandala/core/protocol"
)

// Handler 处理单个本地连接
type Handler struct {
	Config *config.OutboundConfig
}

// HandleConnection 处理 SOCKS5 请求并转发
func (h *Handler) HandleConnection(localConn net.Conn) {
	defer localConn.Close()

	// 1. SOCKS5 握手 (无需认证)
	buf := make([]byte, 262)
	if _, err := io.ReadFull(localConn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	localConn.Write([]byte{0x05, 0x00})

	// 2. 读取客户端请求
	n, err := io.ReadFull(localConn, buf[:4])
	if err != nil || n < 4 {
		return
	}
	cmd := buf[1]
	atyp := buf[3]
	var targetHost string
	var targetPort int
	if cmd != 0x01 {
		return
	}

	// 解析目标地址
	switch atyp {
	case 0x01: // IPv4
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(localConn, ipBuf); err != nil {
			return
		}
		targetHost = net.IP(ipBuf).String()
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(localConn, lenBuf); err != nil {
			return
		}
		domainLen := int(lenBuf[0])
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(localConn, domainBuf); err != nil {
			return
		}
		targetHost = string(domainBuf)
	case 0x04: // IPv6
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(localConn, ipBuf); err != nil {
			return
		}
		targetHost = net.IP(ipBuf).String()
	default:
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(localConn, portBuf); err != nil {
		return
	}
	targetPort = int(portBuf[0])<<8 | int(portBuf[1])

	// 3. 连接远程代理服务器
	dialer := NewDialer(h.Config)
	remoteConn, err := dialer.Dial()
	if err != nil {
		log.Printf("[Proxy] Dial remote failed: %v", err)
		localConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remoteConn.Close()

	// 4. 发送协议头 (握手)
	proxyType := strings.ToLower(h.Config.Type)
	isVless := false
	switch proxyType {
	case "mandala":
		client := protocol.NewMandalaClient(h.Config.Username, h.Config.Password)
		payload, err := client.BuildHandshakePayload(targetHost, targetPort)
		if err != nil {
			log.Printf("[Mandala] Build payload failed: %v", err)
			return
		}
		if _, err := remoteConn.Write(payload); err != nil {
			log.Printf("[Mandala] Handshake write failed: %v", err)
			return
		}
	case "trojan":
		payload, err := protocol.BuildTrojanPayload(h.Config.Password, targetHost, targetPort)
		if err != nil {
			log.Printf("[Trojan] Build payload failed: %v", err)
			return
		}
		if _, err := remoteConn.Write(payload); err != nil {
			log.Printf("[Trojan] Handshake write failed: %v", err)
			return
		}
	case "vless":
		payload, err := protocol.BuildVlessPayload(h.Config.UUID, targetHost, targetPort)
		if err != nil {
			log.Printf("[Vless] Build payload failed: %v", err)
			return
		}
		if _, err := remoteConn.Write(payload); err != nil {
			log.Printf("[Vless] Handshake write failed: %v", err)
			return
		}
		isVless = true
	case "shadowsocks":
		payload, err := protocol.BuildShadowsocksPayload(targetHost, targetPort)
		if err != nil {
			log.Printf("[Shadowsocks] Build payload failed: %v", err)
			return
		}
		if _, err := remoteConn.Write(payload); err != nil {
			log.Printf("[Shadowsocks] Handshake write failed: %v", err)
			return
		}
	case "socks", "socks5":
		err := protocol.HandshakeSocks5(remoteConn, h.Config.Username, h.Config.Password, targetHost, targetPort)
		if err != nil {
			log.Printf("[Socks5] Handshake failed: %v", err)
			return
		}
	default:
		log.Println("[Proxy] Protocol not implemented:", proxyType)
		return
	}

	// 如果是 VLESS，包装连接以剥离响应头
	if isVless {
		remoteConn = protocol.NewVlessConn(remoteConn)
	}

	// 5. 告知本地客户端连接成功
	if _, err := localConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// 6. 双向转发 (优化版：处理半关闭，防止接收数据中断)
	localConn.SetDeadline(time.Time{})
	remoteConn.SetDeadline(time.Time{})

	// 优化 TCP 参数：开启 NoDelay 和 KeepAlive
	if tcpl, ok := localConn.(*net.TCPConn); ok {
		tcpl.SetNoDelay(true)
		tcpl.SetKeepAlive(true)
		tcpl.SetKeepAlivePeriod(30 * time.Second)
	}
	if tcpr, ok := remoteConn.(*net.TCPConn); ok {
		tcpr.SetNoDelay(true)
		tcpr.SetKeepAlive(true)
		tcpr.SetKeepAlivePeriod(30 * time.Second)
		// 尝试设置 MSS 防止碎片 (可选)
		if f, err := tcpr.File(); err == nil {
			_ = syscall.SetsockoptInt(int(f.Fd()), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, 1360)
		}
	}

	// 使用通道等待两个方向的传输完成
	done := make(chan struct{}, 2)

	// 上行：Local -> Remote (上传)
	go func() {
		// io.Copy 内部会自动使用较大的缓冲区 (32KB)，比手动循环更高效
		io.Copy(remoteConn, localConn)
		
		// 发送完数据后，尝试给远程发 FIN (TCP Half-Close)，但不直接关闭连接
		// 这样远程服务器知道我们发完了，但我们还可以继续接收它的响应
		if tcpRemote, ok := remoteConn.(*net.TCPConn); ok {
			tcpRemote.CloseWrite()
		} else if cw, ok := remoteConn.(interface{ CloseWrite() error }); ok {
			// 兼容其他实现了 CloseWrite 的连接类型
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()

	// 下行：Remote -> Local (下载)
	go func() {
		io.Copy(localConn, remoteConn)
		
		// 接收完数据后，尝试给本地发 FIN
		if tcpLocal, ok := localConn.(*net.TCPConn); ok {
			tcpLocal.CloseWrite()
		}
		done <- struct{}{}
	}()

	// 等待两个方向全部完成，或者任何一方发生错误导致 io.Copy 退出
	// 必须等待两次，确保双向数据都已处理完毕
	<-done
	<-done

	// 全部结束，安全关闭连接
	localConn.Close()
	remoteConn.Close()
}
