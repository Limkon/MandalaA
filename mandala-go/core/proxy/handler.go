// 文件路徑: mandala-go/core/proxy/handler.go

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

// Handler 處理單個本地連接
type Handler struct {
	Config *config.OutboundConfig
}

// HandleConnection 處理 SOCKS5 請求並轉發
func (h *Handler) HandleConnection(localConn net.Conn) {
	defer localConn.Close()

	// 1. 本地 SOCKS5 握手階段 (App -> Local Server)
	// 讀取 [版本, 方法數量]
	header := make([]byte, 2)
	if _, err := io.ReadFull(localConn, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return
	}

	// [關鍵修復] 必須讀取並消費掉 App 發送的所有方法列表 (Methods)
	// 否則後續讀取請求頭時，會讀到上一個階段殘留的位元組，導致解析偏移並斷流
	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(localConn, methods); err != nil {
		return
	}

	// 回應 App：選擇「無需認證」(0x00)，因為 App 與本地核心之間不需要額外密碼
	if _, err := localConn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. 讀取 App 的連接請求 (Request)
	// 格式: [版本(5), 指令(1), 保留(0), 地址類型(1)]
	requestHead := make([]byte, 4)
	if _, err := io.ReadFull(localConn, requestHead); err != nil {
		return
	}

	cmd := requestHead[1]
	atyp := requestHead[3]

	// 僅支持 CONNECT 指令 (0x01)
	if cmd != 0x01 {
		return
	}

	var targetHost string
	var targetPort int

	// 解析目標地址 (IPv4, Domain 或 IPv6)
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

	// 讀取埠號 (2位元組, Big Endian)
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(localConn, portBuf); err != nil {
		return
	}
	targetPort = int(portBuf[0])<<8 | int(portBuf[1])

	// 3. 連接遠程伺服器 (Local Server -> Remote Server)
	dialer := NewDialer(h.Config)
	remoteConn, err := dialer.Dial()
	if err != nil {
		log.Printf("[Proxy] 連接遠程伺服器失敗: %v", err)
		// 告知 App：連接失敗 (0x04 主機不可達)
		localConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remoteConn.Close()

	// 4. 根據配置執行對應協議的遠程握手
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
		// 調用修復後的 SOCKS5 握手函數，支援用戶名密碼認證
		err := protocol.HandshakeSocks5(remoteConn, h.Config.Username, h.Config.Password, targetHost, targetPort)
		if err != nil {
			log.Printf("[Socks5] 遠程握手失敗: %v", err)
			return
		}
	}

	// VLESS 特殊處理
	if isVless {
		remoteConn = protocol.NewVlessConn(remoteConn)
	}

	// 5. 告知本地 App 連接成功 (標準 10 位元組響應)
	if _, err := localConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// 6. 雙向轉發流量
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
