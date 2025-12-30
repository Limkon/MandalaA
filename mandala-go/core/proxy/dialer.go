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

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/dns/dnsmessage"
)

func init() {
	// 初始化随机数种子。
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
			// 尝试解析 ECH 配置
			// 注意：生产环境建议添加缓存机制，避免每次连接都进行 DNS 查询
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			configs, err := resolveECHConfig(ctx, d.Config.TLS.ECHDoHURL, d.Config.TLS.ECHPublicName)
			cancel()
			
			if err == nil && len(configs) > 0 {
				echConfigList = configs
				// fmt.Println("[ECH] Config fetched successfully")
			} else {
				// ECH 获取失败，可以选择降级或报错。这里选择降级为普通 TLS，但打印日志
				fmt.Printf("[ECH] Warning: Fetch failed for %s: %v. Fallback to standard TLS.\n", d.Config.TLS.ECHPublicName, err)
			}
		}

		// [Step 2] 构建 uTLS 配置
		// uTLS 的 Config 结构体尽量兼容标准库，但多了 ECH 字段
		uTlsConfig := &utls.Config{
			ServerName:         d.Config.TLS.ServerName,
			InsecureSkipVerify: d.Config.TLS.Insecure,
			MinVersion:         tls.VersionTLS12,
			
			// 填入解析到的 ECH 密钥 (如果为空，uTLS 会自动忽略，行为等同于普通 TLS)
			EncryptedClientHelloConfigList: echConfigList,
		}

		if uTlsConfig.ServerName == "" {
			uTlsConfig.ServerName = d.Config.Server
		}

		// [Step 3] 处理分片 (Fragment)
		// 即使使用 uTLS，底层的 FragmentConn 依然有效，用于在 TCP 层拆分 ClientHello
		var uConn *utls.UConn
		if d.Config.Settings.Fragment {
			fragmentConn := &FragmentConn{Conn: conn, active: true}
			// 使用 uTLS 包装分片连接
			// HelloChrome_Auto 模拟 Chrome 指纹，这是 ECH 能够成功伪装的关键
			uConn = utls.UClient(fragmentConn, uTlsConfig, utls.HelloChrome_Auto)
		} else {
			uConn = utls.UClient(conn, uTlsConfig, utls.HelloChrome_Auto)
		}

		// [Step 4] 执行握手
		if err := uConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("utls handshake failed: %v", err)
		}
		conn = uConn
	}

	// [Step 5] WebSocket 处理 (保持原有逻辑不变)
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

// resolveECHConfig 通过 DoH 获取 HTTPS 记录中的 ECH 配置
func resolveECHConfig(ctx context.Context, dohURL string, domain string) ([]byte, error) {
	// 1. 构造 DNS 查询 (Type 65 - HTTPS)
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 0,
		Response:           false,
		OpCode:             0,
		Authoritative:      false,
		Truncated:          false,
		RecursionDesired:   true,
		RecursionAvailable: false,
		RCode:              0,
	})
	b.StartQuestions()
	b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(domain + "."),
		Type:  65, // TypeHTTPS
		Class: dnsmessage.ClassINET,
	})
	msg, err := b.Finish()
	if err != nil {
		return nil, err
	}

	// 2. 发送 DoH 请求
	req, err := http.NewRequestWithContext(ctx, "POST", dohURL, strings.NewReader(string(msg)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	// 使用短超时的 Client
	client := &http.Client{}
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
	var p dnsmessage.Parser
	if _, err := p.Start(body); err != nil {
		return nil, err
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}

	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}

		if h.Type == 65 { // HTTPS
			r, err := p.HTTPSResource()
			if err != nil {
				// 解析资源体失败，跳过
				if err := p.SkipAnswer(); err != nil {
					return nil, err
				}
				continue
			}
			
			// 遍历 Key-Value 对，寻找 ech (key=5)
			for _, val := range r.Values {
				if val.Key == 5 {
					return val.Value, nil
				}
			}
		}

		if err := p.SkipAnswer(); err != nil {
			return nil, err
		}
	}

	return nil, fmt.Errorf("no ECH config found")
}

// FragmentConn 用于在 TLS 握手初期拆分数据包 (保持原有逻辑)
type FragmentConn struct {
	net.Conn
	active bool
}

func (f *FragmentConn) Write(b []byte) (int, error) {
	// uTLS 的 ClientHello 依然符合 TLS 记录层格式 (0x16 开头)
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
	buf = append(buf, 0x82) // Binary Frame

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
