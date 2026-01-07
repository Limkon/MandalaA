package proxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"mandala/core/config"

	"github.com/coder/websocket"
	"github.com/miekg/dns"
	utls "github.com/refraction-networking/utls"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// ECH 缓存 (以域名为 Key)
var (
	echCache      = make(map[string][]byte)
	echCacheMutex sync.RWMutex
)

type Dialer struct {
	Config *config.OutboundConfig
}

func NewDialer(cfg *config.OutboundConfig) *Dialer {
	return &Dialer{Config: cfg}
}

// Dial 建立连接
func (d *Dialer) Dial() (net.Conn, error) {
	// 1. 基础 TCP 连接
	targetAddr := fmt.Sprintf("%s:%d", d.Config.Server, d.Config.ServerPort)
	conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	// 2. 准备 TLS/uTLS 连接
	isTLSEstablished := false
	
	if d.Config.TLS != nil && d.Config.TLS.Enabled {
		var echConfigList []byte
		
		// [ECH 逻辑]
		if d.Config.TLS.EnableECH {
			// 确定查询域名: 优先 ECHPublicName, 其次 ServerName
			queryDomain := d.Config.TLS.ECHPublicName
			if queryDomain == "" {
				queryDomain = d.Config.TLS.ServerName
			}
			
			// 1. 查内存缓存
			echCacheMutex.RLock()
			cached, ok := echCache[queryDomain]
			echCacheMutex.RUnlock()

			if ok {
				echConfigList = cached
				fmt.Printf("[ECH] 使用缓存密钥: %s (长度: %d)\n", queryDomain, len(cached))
			} else {
				// 2. 缓存未命中，执行 DoH 查询
				dohURL := d.Config.TLS.ECHDoHURL
				if dohURL == "" {
					dohURL = "https://1.1.1.1/dns-query" // 默认 DoH
				}

				fmt.Printf("[ECH] 开始获取密钥 | DoH: %s | SNI: %s\n", dohURL, queryDomain)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) 
				configs, err := resolveECHConfig(ctx, dohURL, queryDomain)
				cancel()

				if err == nil && len(configs) > 0 {
					echConfigList = configs
					// 写入缓存
					echCacheMutex.Lock()
					echCache[queryDomain] = configs
					echCacheMutex.Unlock()
					fmt.Printf("[ECH] 密钥获取成功! 已存入缓存。\n")
				} else {
					fmt.Printf("[ECH] 错误: 密钥获取失败: %v\n", err)
					// 注意：此处失败后继续运行，会降级为普通 TLS，可能导致连接被阻断
				}
			}
		}

		// [关键修复] 动态设置 TLS 版本
		// ECH 规范要求必须使用 TLS 1.3
		minVer := uint16(tls.VersionTLS12)
		if len(echConfigList) > 0 {
			minVer = tls.VersionTLS13
			fmt.Println("[ECH] 已强制设置 MinVersion = TLS 1.3")
		}

		uTlsConfig := &utls.Config{
			ServerName:         d.Config.TLS.ServerName,
			InsecureSkipVerify: d.Config.TLS.Insecure,
			MinVersion:         minVer, // 使用动态版本
			NextProtos:         []string{"http/1.1"},
			EncryptedClientHelloConfigList: echConfigList,
		}

		if uTlsConfig.ServerName == "" {
			uTlsConfig.ServerName = d.Config.Server
		}

		// 处理 TCP 层分片
		if d.Config.Settings.Fragment {
			conn = &FragmentConn{Conn: conn, active: true}
		}

		// 使用 HelloChrome_Auto 指纹
		uConn := utls.UClient(conn, uTlsConfig, utls.HelloChrome_Auto)

		if err := uConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("utls handshake failed: %v", err)
		}
		
		conn = uConn
		isTLSEstablished = true
	}

	// 3. 处理 WebSocket
	if d.Config.Transport != nil && d.Config.Transport.Type == "ws" {
		scheme := "ws"
		if d.Config.TLS != nil && d.Config.TLS.Enabled && !isTLSEstablished {
			scheme = "wss"
		}
		
		path := d.Config.Transport.Path
		if path == "" {
			path = "/"
		}
		
		host := d.Config.TLS.ServerName
		if host == "" {
			host = d.Config.Server
		}
		
		wsURL := fmt.Sprintf("%s://%s%s", scheme, host, path)
		
		headers := make(http.Header)
		if d.Config.Transport.Headers != nil {
			for k, v := range d.Config.Transport.Headers {
				headers.Set(k, v)
			}
		}
		headers.Set("Host", host)

		httpClient := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return conn, nil
				},
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		opts := &websocket.DialOptions{
			HTTPClient: httpClient,
			HTTPHeader: headers,
			CompressionMode: websocket.CompressionDisabled,
		}

		wsConn, _, err := websocket.Dial(ctx, wsURL, opts)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("websocket dial failed: %v", err)
		}

		return websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary), nil
	}

	return conn, nil
}

// resolveECHConfig 获取 ECH 配置 (含详细调试日志)
func resolveECHConfig(ctx context.Context, dohURL string, domain string) ([]byte, error) {
	// 1. 构造 DNS 问题
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
	data, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("DNS Pack 失败: %v", err)
	}

	// 2. Base64Url 编码
	b64Query := base64.RawURLEncoding.EncodeToString(data)
	
	// 3. 拼接 URL
	var reqURL string
	if strings.Contains(dohURL, "?") {
		reqURL = fmt.Sprintf("%s&dns=%s", dohURL, b64Query)
	} else {
		reqURL = fmt.Sprintf("%s?dns=%s", dohURL, b64Query)
	}

	fmt.Printf("[ECH-Debug] 请求 URL: %s\n", reqURL)

	// 4. 发起 HTTP 请求
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 忽略证书验证以提高成功率
			ResponseHeaderTimeout: 5 * time.Second,
		},
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP 请求错误: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP 状态码错误: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %v", err)
	}
	
	fmt.Printf("[ECH-Debug] 收到响应，大小: %d 字节\n", len(body))

	// 5. 解析 DNS 响应
	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(body); err != nil {
		return nil, fmt.Errorf("DNS Unpack 失败: %v", err)
	}

	// 6. 提取 HTTPS 记录
	for _, ans := range respMsg.Answer {
		if https, ok := ans.(*dns.HTTPS); ok {
			// fmt.Printf("[ECH-Debug] 找到 HTTPS 记录，Priority: %d\n", https.Priority)
			for _, val := range https.Value {
				if ech, ok := val.(*dns.SVCBECHConfig); ok {
					fmt.Printf("[ECH-Debug] >>> 成功提取 ECH Config! (长度: %d) <<<\n", len(ech.ECH))
					return ech.ECH, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("响应中未包含有效的 ECH 配置")
}

// FragmentConn 保持不变
type FragmentConn struct {
	net.Conn
	active bool
}

func (f *FragmentConn) Write(b []byte) (int, error) {
	if f.active && len(b) > 50 && b[0] == 0x16 {
		f.active = false
		cut := 5 + rand.Intn(10)
		n1, err := f.Conn.Write(b[:cut])
		if err != nil {
			return n1, err
		}
		time.Sleep(time.Duration(rand.Intn(5)) * time.Millisecond)
		n2, err := f.Conn.Write(b[cut:])
		return n1 + n2, err
	}
	return f.Conn.Write(b)
}
