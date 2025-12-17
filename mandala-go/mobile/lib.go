package mobile

import (
	"fmt"
	"mandala/core/proxy"
)

// Start 启动 Go 核心服务
// localPort: 本地 SOCKS5 监听端口
// jsonConfig: 节点配置 JSON 字符串
func Start(localPort int, jsonConfig string) string {
	err := proxy.Start(localPort, jsonConfig)
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}
	return "" // 返回空字符串表示成功
}

// Stop 停止服务
func Stop() {
	proxy.Stop()
}

// IsRunning 检查服务状态
func IsRunning() bool {
	return proxy.IsRunning()
}
