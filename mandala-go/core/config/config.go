package config

import (
	"encoding/json"
	"fmt"
)

// OutboundConfig 定义了单个代理节点的配置信息
type OutboundConfig struct {
	Tag        string `json:"tag"`
	Type       string `json:"type"` // 协议类型: "mandala", "vless", "trojan", "shadowsocks", "socks"
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	
	// 鉴权字段
	UUID     string `json:"uuid,omitempty"`     // VLESS/VMess 使用
	Password string `json:"password,omitempty"` // Mandala/Trojan/Shadowsocks 使用
	Username string `json:"username,omitempty"` // SOCKS5 使用

	// [新增] 日志配置
	LogPath string `json:"log_path,omitempty"` // 日志文件保存路径

	// 高级配置
	TLS       *TLSConfig       `json:"tls,omitempty"`
	Transport *TransportConfig `json:"transport,omitempty"`

	// [新增] 协议功能设置，对应 Android 端生成的 settings 字段
	Settings *ProtocolSettings `json:"settings,omitempty"`
}

// [新增] ProtocolSettings 定义核心功能的开关与自定义参数
type ProtocolSettings struct {
	VpnMode      bool `json:"vpn_mode"`      // 是否开启 VPN 模式
	Fragment     bool `json:"fragment"`      // 是否开启 TLS 分片
	FragmentSize int  `json:"fragment_size"` // 自定义分片大小 (字节)
	Noise        bool `json:"noise"`         // 是否开启随机填充
	NoiseSize    int  `json:"noise_size"`    // 自定义最大填充大小 (字节)
}

// TLSConfig 定义 TLS 相关配置
type TLSConfig struct {
	Enabled    bool   `json:"enabled"`
	ServerName string `json:"server_name,omitempty"` // SNI
	Insecure   bool   `json:"insecure,omitempty"`    // 是否跳过证书验证
}

// TransportConfig 定义传输层配置 (如 WebSocket)
type TransportConfig struct {
	Type    string            `json:"type"` // "ws" 等
	Path    string            `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// Config 是传递给核心启动函数的总配置结构
type Config struct {
	CurrentNode *OutboundConfig `json:"current_node"`
	LocalPort   int  `json:"local_port"`
	Debug     bool `json:"debug"`
}

// ParseConfig 解析 JSON 字符串为配置对象
func ParseConfig(jsonStr string) (*OutboundConfig, error) {
	var cfg OutboundConfig
	err := json.Unmarshal([]byte(jsonStr), &cfg)
	if err != nil {
		return nil, fmt.Errorf("config parse error: %v", err)
	}
	return &cfg, nil
}
