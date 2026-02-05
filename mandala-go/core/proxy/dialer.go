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

// ECH 缓存
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

// Dial 主入口：优化的握手逻辑
func (d *Dialer) Dial() (net.Conn, error) {
	// [Critical Fix] 针对 WebSocket 强制使用 HTTP/1.1
	// 这一步是为了对齐 C 语言版的行为，避免 "H2协商 -> 失败 -> 断开重连" 的高延迟循环。
	// Cloudflare 等 CDN 会强制优先 H2，如果不预先禁用，会导致 WebSocket 连接 100% 触发重连逻辑。
	forceH1 := false
	if d.Config.Transport != nil && d.Config.Transport.Type == "ws" {
		forceH1 = true
	}

	// 第一次尝试连接就根据情况决定是否强制 H1
	conn, negotiated, err := d.handshake(forceH1)
	if err != nil {
		return nil, err
	}

	// 双重保险：如果仍然意外协商出了 h2 (极罕见)，才走退回逻辑
	if negotiated == "h2" && d.Config.Transport != nil && d.Config.Transport.Type == "ws" {
		fmt.Println("[Handshake] 警告：意外协商出 h2，正在执行退回重试...")
		conn.Close()
		conn, _, err = d.handshake(true)
		if err != nil {
			return nil, fmt.Errorf("fallback handshake failed: %v", err)
		}
	}

	// 握手完成，处理 WebSocket 升级
	if d.Config.Transport != nil && d.Config.Transport.Type == "ws" {
		return d.upgradeWebsocket(conn)
	}

	return conn, nil
}

// handshake 执行底层的 TCP 连接和 TLS 握手
// forceH1: 是否强制只使用 http/1.1 (剔除 h2)
func (d *Dialer) handshake(forceH1 bool) (net.Conn, string, error) {
	// 1. 基础 TCP 连接
	targetAddr := fmt.Sprintf("%s:%d", d.Config.Server, d.Config.ServerPort)
	conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		return nil, "", err
	}

	if d.Config.TLS == nil || !d.Config.TLS.Enabled {
		return conn, "", nil
	}

	// 2. TLS/ECH 逻辑
	var echConfigList []byte
	if d.Config.TLS.EnableECH {
		echConfigList = d.getECHConfig()
	}

	minVer := uint16(tls.VersionTLS12)
	if len(echConfigList) > 0 {
		minVer = tls.VersionTLS13
	}

	uTlsConfig := &utls.Config{
		ServerName:         d.Config.TLS.ServerName,
		InsecureSkipVerify: d.Config.TLS.Insecure,
		MinVersion:         minVer,
		// 默认声称支持 h2 和 http/1.1
		NextProtos:                     []string{"h2", "http/1.1"},
		EncryptedClientHelloConfigList: echConfigList,
	}

	if uTlsConfig.ServerName == "" {
		uTlsConfig.ServerName = d.Config.Server
	}

	if d.Config.Settings.Fragment {
		conn = &FragmentConn{Conn: conn, active: true}
	}

	uConn := utls.UClient(conn, uTlsConfig, utls.HelloCustom)
	
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("spec error: %v", err)
	}

	// [关键逻辑] 根据 forceH1 参数调整 ALPN
	if forceH1 {
		// 强制剔除 h2，只留 http/1.1
		foundALPN := false
		for i, ext := range spec.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = []string{"http/1.1"}
				spec.Extensions[i] = alpn
				foundALPN = true
				break
			}
		}
		if !foundALPN {
			spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
		}
	}

	if err := uConn.ApplyPreset(&spec); err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("preset error: %v", err)
	}

	if err := uConn.Handshake(); err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("handshake failed: %v", err)
	}

	return uConn, uConn.ConnectionState().NegotiatedProtocol, nil
}

// getECHConfig 保持不变
func (d *Dialer) getECHConfig() []byte {
	queryDomain := d.Config.TLS.ECHPublicName
	if queryDomain == "" {
		queryDomain = d.Config.TLS.ServerName
	}

	echCacheMutex.RLock()
	cached, ok := echCache[queryDomain]
	echCacheMutex.RUnlock()

	if ok {
		fmt.Printf("[ECH] 使用缓存密钥: %s\n", queryDomain)
		return cached
	}

	dohURL := d.Config.TLS.ECHDoHURL
	if dohURL == "" {
		dohURL = "https://1.1.1.1/dns-query"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	
	configs, err := resolveECHConfig(ctx, dohURL, queryDomain)
	if err == nil && len(configs) > 0 {
		echCacheMutex.Lock()
		echCache[queryDomain] = configs
		echCacheMutex.Unlock()
		fmt.Printf("[ECH] 密钥获取成功\n")
		return configs
	}
	
	fmt.Printf("[ECH] 警告: 获取失败: %v\n", err)
	return nil
}

// upgradeWebsocket 保持不变
func (d *Dialer) upgradeWebsocket(conn net.Conn) (net.Conn, error) {
	scheme := "ws"
	
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

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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

// resolveECHConfig 保持不变
func resolveECHConfig(ctx context.Context, dohURL string, domain string) ([]byte, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
	data, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack: %v", err)
	}

	b64Query := base64.RawURLEncoding.EncodeToString(data)
	
	var reqURL string
	if strings.Contains(dohURL, "?") {
		reqURL = fmt.Sprintf("%s&dns=%s", dohURL, b64Query)
	} else {
		reqURL = fmt.Sprintf("%s?dns=%s", dohURL, b64Query)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			ResponseHeaderTimeout: 5 * time.Second,
		},
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status: %d", resp.StatusCode)
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

	return nil, fmt.Errorf("no ech found")
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
