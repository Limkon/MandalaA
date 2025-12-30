package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"mandala/core/config"

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

func (d *Dialer) Dial() (net.Conn, error) {
	targetAddr := fmt.Sprintf("%s:%d", d.Config.Server, d.Config.ServerPort)
	conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}

	if d.Config.TLS != nil && d.Config.TLS.Enabled {
		// [Step 1] 准备 ECH 配置
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

		// [Step 2] 构建 uTLS 配置
		uTlsConfig := &utls.Config{
			ServerName:         d.Config.TLS.ServerName,
			InsecureSkipVerify: d.Config.TLS.Insecure,
			MinVersion:         tls.VersionTLS12,
			// 这里设置 NextProtos 可能被 HelloChrome_Auto 忽略，所以下面需要手动修改 Spec
			NextProtos:                     []string{"http/1.1"},
			EncryptedClientHelloConfigList: echConfigList,
		}

		if uTlsConfig.ServerName == "" {
			uTlsConfig.ServerName = d.Config.Server
		}

		// [Step 3] 构建 uTLS 连接 (关键修改：使用 HelloCustom 并手动修补 ALPN)
		var uConn *utls.UConn
		// 使用 HelloCustom 允许我们应用修改后的 Spec
		if d.Config.Settings.Fragment {
			fragmentConn := &FragmentConn{Conn: conn, active: true}
			uConn = utls.UClient(fragmentConn, uTlsConfig, utls.HelloCustom)
		} else {
			uConn = utls.UClient(conn, uTlsConfig, utls.HelloCustom)
		}

		// --- 核心修复开始 ---
		// 1. 获取 Chrome 浏览器的默认指纹模版
		// 注意：uTLS 版本不同，GetClientHelloSpec 的签名可能不同，这里假设是返回 *ClientHelloSpec 无错误
		// 如果编译报错说返回值数量不对，请告诉我，我调整代码
		spec := utls.HelloChrome_Auto.GetClientHelloSpec(uTlsConfig)

		// 2. 遍历指纹中的扩展，找到 ALPN 扩展
		foundALPN := false
		for i, ext := range spec.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				// 3. 强制将其修改为只支持 http/1.1
				// 这样服务器就绝对不会发送 HTTP/2 数据了
				alpn.AlpnProtocols = []string{"http/1.1"}
				spec.Extensions[i] = alpn
				foundALPN = true
				break
			}
		}

		// 如果原指纹没 ALPN (不太可能)，我们手动补一个
		if !foundALPN {
			spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
		}

		// 4. 应用这个修补后的指纹
		if err := uConn.ApplyPreset(spec); err != nil {
			conn.Close()
			return nil, fmt.Errorf("apply preset failed: %v", err)
		}
		// --- 核心修复结束 ---

		// 执行握手
		if err := uConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("utls handshake failed: %v", err)
		}
		conn = uConn
	}

	// [Step 4] WebSocket 处理
	if d.Config.Transport != nil && d.Config.Transport.Type == "ws" {
		wsConn, err := d.handshakeWebSocket(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("websocket handshake failed: %v", err)
		}
		return wsConn, nil
	}

	return conn, nil
}

// resolveECHConfig 保持不变 (使用 miekg/dns)
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
				// 确认类型为 SVCBECHConfig
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

// handshakeWebSocket 保持不变
func (d *Dialer) handshakeWebSocket(conn net.Conn) (net.Conn, error) {
	path := d.Config.Transport.Path
	if path == "" {
		path = "/"
	}
	host := d.Config.TLS.ServerName
	if host == "" {
		host = d.Config.Server
	}

	key := make([]byte, 16)
	rand.Read(key)
	keyStr := base64.StdEncoding.EncodeToString(key)

	req := fmt.Sprintf("GET %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n", path, host, keyStr)

	if d.Config.Transport.Headers != nil {
		for k, v := range d.Config.Transport.Headers {
			req += fmt.Sprintf("%s: %s\r\n", k, v)
		}
	}
	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 101 {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return NewWSConn(conn, br), nil
}

// WSConn 保持不变
type WSConn struct {
	net.Conn
	reader    *bufio.Reader
	remaining int64
}

func NewWSConn(c net.Conn, br *bufio.Reader) *WSConn {
	return &WSConn{Conn: c, reader: br, remaining: 0}
}

func (w *WSConn) Write(b []byte) (int, error) {
	length := len(b)
	if length == 0 {
		return 0, nil
	}

	buf := make([]byte, 0, 14+length)
	buf = append(buf, 0x82)

	if length < 126 {
		buf = append(buf, byte(length)|0x80)
	} else if length <= 65535 {
		buf = append(buf, 126|0x80)
		buf = binary.BigEndian.AppendUint16(buf, uint16(length))
	} else {
		buf = append(buf, 127|0x80)
		buf = binary.BigEndian.AppendUint64(buf, uint64(length))
	}

	maskKey := make([]byte, 4)
	rand.Read(maskKey)
	buf = append(buf, maskKey...)

	payloadStart := len(buf)
	buf = append(buf, b...)

	for i := 0; i < length; i++ {
		buf[payloadStart+i] ^= maskKey[i%4]
	}

	if _, err := w.Conn.Write(buf); err != nil {
		return 0, err
	}
	return length, nil
}

func (w *WSConn) Read(b []byte) (int, error) {
	for {
		if w.remaining > 0 {
			limit := int64(len(b))
			if w.remaining < limit {
				limit = w.remaining
			}
			n, err := w.reader.Read(b[:limit])
			if n > 0 {
				w.remaining -= int64(n)
			}
			if n > 0 || err != nil {
				return n, err
			}
		}

		header, err := w.reader.ReadByte()
		if err != nil {
			return 0, err
		}

		opcode := header & 0x0F
		lenByte, err := w.reader.ReadByte()
		if err != nil {
			return 0, err
		}

		masked := (lenByte & 0x80) != 0
		payloadLen := int64(lenByte & 0x7F)

		if payloadLen == 126 {
			lenBuf := make([]byte, 2)
			if _, err := io.ReadFull(w.reader, lenBuf); err != nil {
				return 0, err
			}
			payloadLen = int64(binary.BigEndian.Uint16(lenBuf))
		} else if payloadLen == 127 {
			lenBuf := make([]byte, 8)
			if _, err := io.ReadFull(w.reader, lenBuf); err != nil {
				return 0, err
			}
			payloadLen = int64(binary.BigEndian.Uint64(lenBuf))
		}

		if masked {
			if _, err := io.CopyN(io.Discard, w.reader, 4); err != nil {
				return 0, err
			}
		}

		switch opcode {
		case 0x8:
			return 0, io.EOF
		case 0x9, 0xA:
			if payloadLen > 0 {
				io.CopyN(io.Discard, w.reader, payloadLen)
			}
			continue
		case 0x0, 0x1, 0x2:
			w.remaining = payloadLen
			if w.remaining == 0 {
				continue
			}
		default:
			if payloadLen > 0 {
				io.CopyN(io.Discard, w.reader, payloadLen)
			}
			continue
		}
	}
}
