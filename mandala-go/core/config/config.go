// 文件路径: mandala-go/core/config/config.go

package config

import (
	"encoding/json"
	"fmt"
)

// OutboundConfig 定义了单个代理节点的配置信息
type OutboundConfig struct {
	Tag        string `json:"tag"`
	Type       string `json:"type"` // mandala, vless, trojan, shadowsocks, socks
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	
	// 鉴权字段
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	Username string `json:"username,omitempty"`

	// 日志配置
	LogPath string `json:"log_path,omitempty"`

	// 高级配置
	TLS       *TLSConfig       `json:"tls,omitempty"`
	Transport *TransportConfig `json:"transport,omitempty"`
	
	// [新增] 全局功能设置
	Settings  *GlobalSettings  `json:"settings,omitempty"`
	
	// 全局设置 (由 Android 传入)
	LocalPort int `json:"local_port"`
}

// [新增] GlobalSettings 定义了分片和填充的具体参数
type GlobalSettings struct {
	VpnMode       bool `json:"vpn_mode"`
	TlsFragment   bool `json:"fragment"`
	FragmentSize  int  `json:"fragment_size"` // 自定义分片大小
	RandomPadding bool `json:"noise"`
	NoiseSize     int  `json:"noise_size"`    // 自定义填充范围
}

type TLSConfig struct {
	Enabled    bool   `json:"enabled"`
	ServerName string `json:"server_name,omitempty"`
	Insecure   bool   `json:"insecure,omitempty"`
}

type TransportConfig struct {
	Type    string            `json:"type"`
	Path    string            `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type Config struct {
	CurrentNode *OutboundConfig `json:"current_node"`
	LocalPort   int             `json:"local_port"`
	Debug       bool            `json:"debug"`
}

func ParseConfig(jsonStr string) (*OutboundConfig, error) {
	var cfg OutboundConfig
	err := json.Unmarshal([]byte(jsonStr), &cfg)
	if err != nil {
		return nil, fmt.Errorf("config parse error: %v", err)
	}
	return &cfg, nil
}
