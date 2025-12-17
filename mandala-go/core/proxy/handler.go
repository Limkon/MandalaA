package proxy

import (
	"fmt"
	"io"
	"net"
	"strings"
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

	// 设置超时以防恶意扫描挂起连接
	// localConn.SetDeadline(time.Now().Add(30 * time.Second)) 
	// 注意：转发开始后要清除 Deadline

	// 1. SOCKS5 握手 (无需认证)
	// 读取版本号
	buf := make([]byte, 262) // 略大于 SOCKS5 头部
	if _, err := io.ReadFull(localConn, buf[:2]); err != nil {
		return
	}
	// 只要是 SOCKS5 (0x05) 就回复无需认证 (0x00)
	if buf[0] != 0x05 {
		return // 不支持非 SOCKS5
	}
	localConn.Write([]byte{0x05, 0x00})

	// 2. 读取客户端请求 (CONNECT 目标地址)
	// 格式: Ver(1) Cmd(1) Rsv(1) Atyp(1) ...
	n, err := io.ReadFull(localConn, buf[:4])
	if err != nil || n < 4 {
		return
	}

	cmd := buf[1]
	atyp := buf[3]
	var targetHost string
	var targetPort int

	if cmd != 0x01 { // 仅支持 CONNECT
		// 可以在此回复 Command not supported
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
		return // 地址类型不支持
	}

	// 解析端口
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(localConn, portBuf); err != nil {
		return
	}
	targetPort = int(portBuf[0])<<8 | int(portBuf[1])

	// 3. 连接远程代理服务器 (使用我们刚实现的 Dialer)
	dialer := NewDialer(h.Config)
	remoteConn, err := dialer.Dial()
	if err != nil {
		fmt.Printf("[Proxy] Dial remote failed: %v\n", err)
		// SOCKS5 响应: Host unreachable
		localConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remoteConn.Close()

	// 4. 发送协议头 (握手)
	// 根据配置类型决定握手方式
	proxyType := strings.ToLower(h.Config.Type)
	
	switch proxyType {
	case "mandala":
		client := protocol.NewMandalaClient(h.Config.Username, h.Config.Password)
		payload, err := client.BuildHandshakePayload(targetHost, targetPort)
		if err != nil {
			fmt.Printf("[Mandala] Build payload failed: %v\n", err)
			return
		}
		// 写入 remoteConn (如果是 WSConn，这里会被自动封装为 Binary Frame)
		if _, err := remoteConn.Write(payload); err != nil {
			fmt.Printf("[Mandala] Handshake write failed: %v\n", err)
			return
		}
		
	case "vless", "trojan":
		// TODO: 实现 VLESS/Trojan 的头部构造
		// 目前暂不支持，直接断开或记录日志
		fmt.Println("[Proxy] Protocol not implemented yet:", proxyType)
		return
		
	default:
		// 如果是直连或纯 SOCKS，可能不需要复杂握手，视情况而定
	}

	// 5. 告知本地客户端连接成功
	// SOCKS5 响应: Ver(1) Rep(1) Rsv(1) Atyp(1) BindAddr... BindPort...
	// Rep=0x00 (Succeeded)
	if _, err := localConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// 6. 双向转发
	// 清除超时设置，保证长连接不断
	localConn.SetDeadline(time.Time{})
	remoteConn.SetDeadline(time.Time{})

	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(remoteConn, localConn) // Upload
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(localConn, remoteConn) // Download
		errChan <- err
	}()

	// 等待任意一方断开
	<-errChan
}
