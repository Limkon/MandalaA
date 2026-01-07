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

// 简单的内存缓存，避免频繁请求 DoH 导致连接慢
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
		
		// [ECH 逻辑核心]
		if d.Config.TLS.EnableECH {
			// 确定查询使用的域名 (优先使用 PublicName)
			queryDomain := d.Config.TLS.ECHPublicName
			if queryDomain == "" {
				queryDomain = d.Config.TLS.ServerName
			}
			
			// 优先查缓存
			echCacheMutex.RLock()
			cached, ok := echCache[queryDomain]
			echCacheMutex.RUnlock()

			if ok {
				echConfigList = cached
				fmt.Printf("[ECH] 使用缓存配置: %s\n", queryDomain)
			} else {
				// 缓存没有，去请求 DoH
				dohURL := d.Config.TLS.ECHDoHURL
				if dohURL == "" {
					dohURL = "https://1.1.1.1/dns-query" // 默认 Cloudflare
				}

				fmt.Printf("[ECH] 正在从 %s 获取 %s 的密钥...\n", dohURL, queryDomain)
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				configs, err := resolveECHConfig(ctx, dohURL, queryDomain)
				cancel()

				if err == nil && len(configs) > 0 {
					echConfigList = configs
					// 写入缓存
					echCacheMutex.Lock()
					echCache[queryDomain] = configs
					echCacheMutex.Unlock()
					fmt.Printf("[ECH] 密钥获取成功!\n")
				} else {
					// [重要] 获取失败时的策略
					fmt.Printf("[ECH] 错误: 密钥获取失败: %v\n", err)
					// 如果你希望强制 ECH，获取失败就应该返回错误，而不是降级
					// return nil, fmt.Errorf("ECH setup failed: %v", err) 
					fmt.Println("[ECH] 警告: 降级到普通 TLS (可能会被阻断)")
				}
			}
		}

		uTlsConfig := &utls.Config{
			ServerName:         d.Config.TLS.ServerName,
			InsecureSkipVerify: d.Config.TLS.Insecure,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"http/1.1"},
			// [关键] 只要设置了这个字段，utls 会自动处理扩展注入
			EncryptedClientHelloConfigList: echConfigList,
		}

		if uTlsConfig.ServerName == "" {
			uTlsConfig.ServerName = d.Config.Server
		}

		// 处理 TCP 层分片
		if d.Config.Settings.Fragment {
			conn = &FragmentConn{Conn: conn, active: true}
		}

		// 使用 HelloChrome_Auto，它通常包含 ECH 支持
		uConn := utls.UClient(conn, uTlsConfig, utls.HelloChrome_Auto)

		// 显式调用 BuildHandshakeState 可以帮助调试，但通常 ApplyPreset 足够
		if err := uConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("utls handshake failed: %v", err)
		}
		
		conn = uConn
		isTLSEstablished = true
	}

	// 3. 处理 WebSocket
	if d.Config.Transport != nil && d.Config.Transport.Type == "ws" {
		// 如果 TLS 已建立，scheme 必须是 ws (通过加密隧道传输明文 HTTP Upgrade)
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

// resolveECHConfig 使用 GET 方式 (Base64Url) 查询 DoH，穿透性更好
func resolveECHConfig(ctx context.Context, dohURL string, domain string) ([]byte, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)

	data, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	b64Query := base64.RawURLEncoding.EncodeToString(data)
	reqURL := fmt.Sprintf("%s?dns=%s", dohURL, b64Query)
	// 简单处理 URL 参数拼接
	if strings.Contains(dohURL, "?") {
		reqURL = fmt.Sprintf("%s&dns=%s", dohURL, b64Query)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	
	// 使用自定义 Client，避免复用导致的问题
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // DoH 请求本身建议暂时忽略证书，防止鸡生蛋问题
			},
			ResponseHeaderTimeout: 3 * time.Second,
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

	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(body); err != nil {
		return nil, err
	}

	for _, ans := range respMsg.Answer {
		if https, ok := ans.(*dns.HTTPS); ok {
			for _, val := range https.Value {
				if ech, ok := val.(*dns.SVCBECHConfig); ok {
					return ech.ECH, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no ECH config found")
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
