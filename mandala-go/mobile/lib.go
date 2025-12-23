package mobile

import (
	"encoding/json"
	"io"
	"log"
	"mandala/core/config"
	"mandala/core/tun"
	"os"
)

var stack *tun.Stack

// [新增] initLog 初始化日志系统，支持文件和控制台双输出
func initLog(path string) {
	if path == "" {
		return
	}
	
	// 以追加模式打开或创建文件
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("GoLog: 无法打开日志文件 [%s]: %v", path, err)
		return
	}
	
	// 创建多路输出：同时输出到文件和标准输出 (Android Logcat)
	multi := io.MultiWriter(f, os.Stdout)
	log.SetOutput(multi)
	
	// 设置日志格式
	log.SetPrefix("Mandala-Core: ")
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	
	log.Printf("日志系统已初始化。输出路径: %s", path)
}

// StartVpn 启动 VPN 核心，fd 使用 int64 以匹配 Java Long
func StartVpn(fd int64, mtu int64, configJson string) string {
	if stack != nil {
		return "VPN已经在运行"
	}

	var cfg config.OutboundConfig
	if err := json.Unmarshal([]byte(configJson), &cfg); err != nil {
		return "解析配置失败: " + err.Error()
	}

	// [新增] 初始化日志
	if cfg.LogPath != "" {
		initLog(cfg.LogPath)
	}

	// 转换回 int 使用
	s, err := tun.StartStack(int(fd), int(mtu), &cfg)
	if err != nil {
		log.Printf("启动核心失败: %v", err)
		return "启动核心失败: " + err.Error()
	}

	stack = s
	return ""
}

func Stop() {
	if stack != nil {
		log.Println("核心正在停止...")
		stack.Close()
		stack = nil
	}
}

func IsRunning() bool {
	return stack != nil
}
