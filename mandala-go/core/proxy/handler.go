// 文件路径: mandala-go/core/proxy/handler.go

package proxy

import (
	"io"
	"log"
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

	// 1. SOCKS5 握手阶段
	// 读取 [版本, 方法数量]
	header := make([]byte, 2)
	if _, err := io.ReadFull(localConn, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return
	}

	// [关键修复] 必须读取并消费掉客户端发送的所有方法列表 (Methods)
	// 如果不读取这部分，后续读取请求头时会读到残留的方法字节，导致地址解析错误并断流
	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(localConn, methods); err != nil {
		return
	}

	// 回复客户端：选择“无需认证”(0x00)
	if _, err := localConn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. 读取客户端连接请求 (Request)
	// 格式: [版本(5), 指令(1), 保留(0), 地址类型(1)]
	requestHead := make([]byte, 4)
	if _, err := io.ReadFull(localConn, requestHead); err != nil {
		return
	}

	cmd := requestHead[1]
	atyp := requestHead[3]

	// 仅支持 CONNECT 指令 (0x01)
	if cmd != 0x01 {
		return
	}

	var targetHost string
	var targetPort int

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

	// 读取端口 (2字节, Big Endian)
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(localConn, portBuf); err != nil {
		return
	}
	targetPort = int(portBuf[0])<<8 | int(portBuf[1])

	// 3. 连接远程代理服务器
	dialer := NewDialer(h.Config)
	remoteConn, err := dialer.Dial()
	if err != nil {
		log.Printf("[Proxy] 连接远程服务器失败: %v", err)
		// 告知客户端：连接失败 (0x04 主机不可达)
		localConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remoteConn.Close()

	// 4. 发送协议握手头
	proxyType := strings.ToLower(h.Config.Type)
	isVless := false

	switch proxyType {
	case "mandala":
		client := protocol.NewMandalaClient(h.Config.Username, h.Config.Password)
		payload, err := client.BuildHandshakePayload(targetHost, targetPort)
		if err == nil {
			remoteConn.Write(payload)
		}

	case "trojan":
		payload, err := protocol.BuildTrojanPayload(h.Config.Password, targetHost, targetPort)
		if err == nil {
			remoteConn.Write(payload)
		}

	case "vless":
		payload, err := protocol.BuildVlessPayload(h.Config.UUID, targetHost, targetPort)
		if err == nil {
			remoteConn.Write(payload)
		}
		isVless = true

	case "shadowsocks":
		payload, err := protocol.BuildShadowsocksPayload(targetHost, targetPort)
		if err == nil {
			remoteConn.Write(payload)
		}

	case "socks", "socks5":
		err := protocol.HandshakeSocks5(remoteConn, h.Config.Username, h.Config.Password, targetHost, targetPort)
		if err != nil {
			log.Printf("[Socks5] 握手失败: %v", err)
			return
		}
	}

	// 如果是 VLESS，包装连接以剥离响应头
	if isVless {
		remoteConn = protocol.NewVlessConn(remoteConn)
	}

	// 5. 告知本地客户端连接成功 (标准 10 字节响应)
	if _, err := localConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// 6. 双向转发流量
	localConn.SetDeadline(time.Time{})
	remoteConn.SetDeadline(time.Time{})

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
