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
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

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
			} else {
				fmt.Printf("[ECH] Warning: Fetch failed: %v. Fallback to standard TLS.\n", err)
			}
		}

		uTlsConfig := &utls.Config{
			ServerName:         d.Config.TLS.ServerName,
			InsecureSkipVerify: d.Config.TLS.Insecure,
			MinVersion:         tls.VersionTLS12,
			// 显式声明只支持 http/1.1 (虽然会被 HelloCustom 覆盖，但作为兜底)
			NextProtos:                     []string{"http/1.1"},
			EncryptedClientHelloConfigList: echConfigList,
		}

		if uTlsConfig.ServerName == "" {
			uTlsConfig.ServerName = d.Config.Server
		}

		// 处理 TCP 层分片
		if d.Config.Settings.Fragment {
			conn = &FragmentConn{Conn: conn, active: true}
		}

		// [关键修改] 使用 HelloCustom 模式，以便我们可以手动修补指纹
		uConn = utls.UClient(conn, uTlsConfig, utls.HelloCustom)

		// 1. 获取 Chrome 浏览器的默认指纹模版
		// [修复] 使用 UTLSIdToSpec 获取 Spec，而不是调用不存在的方法
		spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to get uTLS spec: %v", err)
		}

		// 2. 遍历指纹中的扩展，找到 ALPN 扩展
		foundALPN := false
		for i, ext := range spec.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				// 3. [核心操作] 强制将其修改为只支持 http/1.1
				// 这会告诉服务器：“我虽然是 Chrome，但我这次只想用 HTTP/1.1”
				// 这样服务器就不会发送 HTTP/2 数据，也就不会触发 "invalid Upgrade header" 错误
				alpn.AlpnProtocols = []string{"http/1.1"}
				spec.Extensions[i] = alpn
				foundALPN = true
				break
			}
		}

		// 如果原指纹没 ALPN (防御性编程)，补一个
		if !foundALPN {
			spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
		}

		// 4. 应用修补后的指纹
		if err := uConn.ApplyPreset(&spec); err != nil {
			conn.Close()
			return nil, fmt.Errorf("apply preset failed: %v", err)
		}

		// 执行 TLS 握手
		if err := uConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("utls handshake failed: %v", err)
		}
		
		conn = uConn
	}

	// 3. 处理 WebSocket
	if d.Config.Transport != nil && d.Config.Transport.Type == "ws" {
		scheme := "ws"
		if d.Config.TLS != nil && d.Config.TLS.Enabled {
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

		// 使用标准 http.Transport，因为我们强制了 HTTP/1.1
		// 这样最稳定，兼容性最好
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

		// 依然使用 coder/websocket 库，因为它处理分片和协议细节更专业
		wsConn, _, err := websocket.Dial(ctx, wsURL, opts)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("websocket dial failed: %v", err)
		}

		return websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary), nil
	}

	return conn, nil
}

// resolveECHConfig 保持不变
func resolveECHConfig(ctx context.Context, dohURL string, domain string) ([]byte, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)

	data, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", dohURL, strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

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
