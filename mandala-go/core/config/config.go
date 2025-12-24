package config

import (
	"encoding/json"
	"fmt"
)

// OutboundConfig 定义了单个代理节点的配置信息
// 对应原项目 config.c 中 ParseNodeConfigToGlobal 解析的字段
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
	// 目前我们只需要关注出站代理配置
	// Android 端通常每次只选中一个节点运行，所以这里也可以简化为单个 OutboundConfig
	// 但为了兼容性和扩展性，我们保留列表形式或直接使用单个对象
	CurrentNode *OutboundConfig `json:"current_node"`
	
	// 全局设置 (对应 set.ini 中的部分设置)
	LocalPort int  `json:"local_port"`
	Debug     bool `json:"debug"`
}

// ParseConfig 解析 JSON 字符串为配置对象
func ParseConfig(jsonStr string) (*OutboundConfig, error) {
	// 为了简化 Android 调用，我们假设传入的是单个节点的 JSON 配置
	var cfg OutboundConfig
	err := json.Unmarshal([]byte(jsonStr), &cfg)
	if err != nil {
		return nil, fmt.Errorf("config parse error: %v", err)
	}
	return &cfg, nil
}
