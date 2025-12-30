package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"mandala/core/config"

	"github.com/coder/websocket"
	"github.com/miekg/dns"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

func init() {
	// 初始化随机数种子
	rand.Seed(time.Now().UnixNano())
}

type Dialer struct {
	Config *config.OutboundConfig
}

func NewDialer(cfg *config.OutboundConfig) *Dialer {
	return &Dialer{Config: cfg}
}

// Dial 建立连接 (支持 TCP, TLS, ECH, WebSocket over H1/H2)
func (d *Dialer) Dial() (net.Conn, error) {
	// 1. 基础 TCP 连接
	targetAddr := fmt.Sprintf("%s:%d", d.Config.Server, d.Config.ServerPort)
	conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	// 2. 准备 TLS/uTLS 连接 (如果启用)
	// 如果启用 TLS，conn 将被升级为 uConn；否则保持为 TCP 连接
	var uConn *utls.UConn
	if d.Config.TLS != nil && d.Config.TLS.Enabled {
		// [ECH] 获取配置
		var echConfigList []byte
		if d.Config.TLS.EnableECH && d.Config.TLS.ECHDoHURL != "" && d.Config.TLS.ECHPublicName != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			configs, err := resolveECHConfig(ctx, d.Config.TLS.ECHDoHURL, d.Config.TLS.ECHPublicName)
			cancel()

			if err == nil && len(configs) > 0 {
				echConfigList = configs
				// fmt.Println("[ECH] Config fetched successfully")
			} else {
				fmt.Printf("[ECH] Warning: Fetch failed: %v. Fallback to standard TLS.\n", err)
			}
		}

		// 构建 uTLS 配置
		uTlsConfig := &utls.Config{
			ServerName:         d.Config.TLS.ServerName,
			InsecureSkipVerify: d.Config.TLS.Insecure,
			MinVersion:         tls.VersionTLS12,
			// 启用 ECH (如果有密钥)
			EncryptedClientHelloConfigList: echConfigList,
		}

		if uTlsConfig.ServerName == "" {
			uTlsConfig.ServerName = d.Config.Server
		}

		// 处理 TCP 层分片 (Fragment)
		if d.Config.Settings.Fragment {
			conn = &FragmentConn{Conn: conn, active: true}
		}

		// 创建 uTLS 客户端
		// 使用 HelloChrome_Auto 指纹，它天然支持 h2 (HTTP/2) 和 http/1.1
		// 因为我们现在有能力处理 HTTP/2，所以不需要再阉割指纹了
		uConn = utls.UClient(conn, uTlsConfig, utls.HelloChrome_Auto)

		// 执行 TLS 握手
		if err := uConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("utls handshake failed: %v", err)
		}
		
		// 握手成功，将 conn 引用更新为加密连接
		conn = uConn
	}

	// 3. 处理 WebSocket (支持 HTTP/1.1 和 HTTP/2)
	if d.Config.Transport != nil && d.Config.Transport.Type == "ws" {
		// 确定 WebSocket URL Scheme
		scheme := "ws"
		if d.Config.TLS != nil && d.Config.TLS.Enabled {
			scheme = "wss"
		}
		
		// 确定路径和 Host
		path := d.Config.Transport.Path
		if path == "" {
			path = "/"
		}
		host := d.Config.TLS.ServerName
		if host == "" {
			host = d.Config.Server
		}
		wsURL := fmt.Sprintf("%s://%s%s", scheme, host, path)

		// 准备 HTTP 头部
		headers := make(http.Header)
		if d.Config.Transport.Headers != nil {
			for k, v := range d.Config.Transport.Headers {
				headers.Set(k, v)
			}
		}

		// [核心逻辑] 根据 ALPN 协商结果智能选择 Transport
		var httpClient *http.Client
		
		// 检查是否协商出了 HTTP/2 ("h2")
		// 注意：只有当 TLS 启用且 uConn 不为空时才可能出现 h2
		if uConn != nil && uConn.ConnectionState().NegotiatedProtocol == "h2" {
			// --- HTTP/2 路径 (RFC 8441 WebSocket over HTTP/2) ---
			// 我们需要显式使用 http2.Transport，并将 DialTLS 钩子指向我们已经建立好的 uConn
			t := &http2.Transport{
				// 重写 DialTLS，直接返回已经握手成功的连接，避免标准库尝试重新握手
				DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
					return uConn, nil
				},
				// 关键：允许 HTTP/2 建立 WebSocket
				AllowHTTP: true, 
				
				// 禁用 Ping 以避免干扰 VLESS/Trojan 协议流
				ReadIdleTimeout: 0,
				PingTimeout:     0,
			}
			httpClient = &http.Client{Transport: t}
		} else {
			// --- HTTP/1.1 路径 ---
			// 使用标准 Transport，同样需要通过 DialContext 或 DialTLSContext 注入连接
			t := &http.Transport{
				// 如果是 TLS 连接 (uConn)
				DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return conn, nil 
				},
				// 强制禁用 HTTP/2 (因为我们已经确定没协商出 h2，或者没开 TLS)
				ForceAttemptHTTP2: false, 
			}

			// 如果是普通 TCP (非 TLS)，http.Transport 会调用 DialContext 而不是 DialTLSContext
			if uConn == nil {
				t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return conn, nil
				}
			}
			httpClient = &http.Client{Transport: t}
		}

		// 开始 WebSocket 握手
		// 设置 10 秒超时
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		opts := &websocket.DialOptions{
			HTTPClient: httpClient,
			HTTPHeader: headers,
			// 禁用压缩，因为 VLESS/Trojan 等代理协议通常已经是加密/压缩数据
			CompressionMode: websocket.CompressionDisabled, 
		}

		// websocket.Dial 会使用我们的 httpClient (包含预设的连接) 发送请求
		wsConn, _, err := websocket.Dial(ctx, wsURL, opts)
		if err != nil {
			// 握手失败，关闭底层连接
			conn.Close()
			return nil, fmt.Errorf("websocket dial failed: %v", err)
		}

		// 将 coder/websocket 的连接转换为标准 net.Conn
		// MessageBinary 模式适用于 VLESS/Trojan 等二进制流代理
		return websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary), nil
	}

	// 如果配置的不是 WebSocket，直接返回底层连接 (TLS 或 TCP)
	return conn, nil
}

// resolveECHConfig 使用 miekg/dns 解析 DoH 响应并提取 ECH 配置
func resolveECHConfig(ctx context.Context, dohURL string, domain string) ([]byte, error) {
	// 1. 构造 DNS 查询 (Type 65 - HTTPS)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)

	// 转换为 wire format
	data, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	// 2. 发送 DoH 请求
	req, err := http.NewRequestWithContext(ctx, "POST", dohURL, strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	// 使用独立的 Client 避免复用问题
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DoH status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 3. 解析 DNS 响应
	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(body); err != nil {
		return nil, err
	}

	// 4. 提取 ECH 配置
	for _, ans := range respMsg.Answer {
		if https, ok := ans.(*dns.HTTPS); ok {
			for _, val := range https.Value {
				// miekg/dns 使用 SVCBECHConfig 类型存储 ECH 数据
				if ech, ok := val.(*dns.SVCBECHConfig); ok {
					return ech.ECH, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no ECH config found")
}

// FragmentConn 用于在 TCP 层面切分 TLS ClientHello 包，以此混淆 DPI
// 这在 ECH 场景下依然有效，作为第二层防护
type FragmentConn struct {
	net.Conn
	active bool
}

func (f *FragmentConn) Write(b []byte) (int, error) {
	// 0x16 是 TLS Handshake 记录头的标志
	// 仅对握手包的首个数据块进行切分
	if f.active && len(b) > 50 && b[0] == 0x16 {
		f.active = false
		// 随机切分位置 (5-15 字节处)
		cut := 5 + rand.Intn(10)
		n1, err := f.Conn.Write(b[:cut])
		if err != nil {
			return n1, err
		}
		// 极短的随机延迟，扰乱基于时间的流量分析
		time.Sleep(time.Duration(rand.Intn(5)) * time.Millisecond)
		n2, err := f.Conn.Write(b[cut:])
		return n1 + n2, err
	}
	// 后续数据直接透传
	return f.Conn.Write(b)
}
