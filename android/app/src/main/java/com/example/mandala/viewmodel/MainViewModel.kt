// 文件路徑: android/app/src/main/java/com/example/mandala/viewmodel/MainViewModel.kt

package com.example.mandala.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import mobile.Mobile // 引用 Gomobile 生成的庫

// 定義節點數據結構
data class Node(
    val tag: String,
    val protocol: String, // "mandala", "vless", "trojan"
    val server: String,
    val port: Int,
    val password: String = "",
    val uuid: String = "",
    val transport: String = "tcp", // "ws", "tcp"
    val isSelected: Boolean = false
)

class MainViewModel : ViewModel() {
    // --- UI 狀態流 ---
    private val _isConnected = MutableStateFlow(false)
    val isConnected = _isConnected.asStateFlow()

    private val _connectionTime = MutableStateFlow("00:00:00")
    val connectionTime = _connectionTime.asStateFlow()

    // 當前選中的節點
    private val _currentNode = MutableStateFlow(
        Node("HK - Mandala VIP", "mandala", "hk.example.com", 443, password = "your-password", transport = "ws")
    )
    val currentNode = _currentNode.asStateFlow()

    // 日誌流
    private val _logs = MutableStateFlow(listOf("[System] Ready"))
    val logs = _logs.asStateFlow()

    // 模擬節點列表數據
    private val _nodes = MutableStateFlow(listOf(
        Node("HK - Mandala VIP", "mandala", "hk.example.com", 443, transport = "ws"),
        Node("JP - Trojan Fast", "trojan", "jp.example.com", 443),
        Node("US - VLESS Direct", "vless", "us.example.com", 80)
    ))
    val nodes = _nodes.asStateFlow()

    // --- 核心操作 ---

    fun toggleConnection() {
        if (_isConnected.value) {
            stopProxy()
        } else {
            startProxy()
        }
    }

    private fun startProxy() {
        viewModelScope.launch {
            try {
                addLog("[Core] Preparing config...")
                val configJson = generateConfigJson(_currentNode.value)
                
                // 調用 Go 核心啟動函數 (監聽本地 10809)
                addLog("[Core] Starting service on port 10809...")
                val error = Mobile.start(10809, configJson)

                if (error.isEmpty()) {
                    _isConnected.value = true
                    addLog("[Core] Service started successfully.")
                    // 這裡可以啟動一個計時器協程來更新 _connectionTime
                } else {
                    addLog("[Error] Start failed: $error")
                    _isConnected.value = false
                }
            } catch (e: Exception) {
                addLog("[Exception] ${e.message}")
            }
        }
    }

    private fun stopProxy() {
        viewModelScope.launch {
            try {
                addLog("[Core] Stopping service...")
                Mobile.stop()
                _isConnected.value = false
                addLog("[Core] Service stopped.")
            } catch (e: Exception) {
                addLog("[Exception] Stop failed: ${e.message}")
            }
        }
    }

    fun selectNode(node: Node) {
        // 如果正在運行，先停止
        if (_isConnected.value) {
            stopProxy()
        }
        _currentNode.value = node
        addLog("[System] Switched to node: ${node.tag}")
    }

    private fun addLog(msg: String) {
        val currentLogs = _logs.value.toMutableList()
        if (currentLogs.size > 100) currentLogs.removeAt(0) // 保持日誌長度
        currentLogs.add(msg)
        _logs.value = currentLogs
    }

    // 生成符合 Go 核心要求的 JSON 配置字符串
    private fun generateConfigJson(node: Node): String {
        // 簡單的手動拼接 JSON，實際項目建議使用 Gson 或 Moshi
        return """
        {
            "tag": "${node.tag}",
            "type": "${node.protocol}",
            "server": "${node.server}",
            "server_port": ${node.port},
            "password": "${node.password}",
            "uuid": "${node.uuid}",
            "tls": {
                "enabled": true,
                "server_name": "${node.server}"
            },
            "transport": {
                "type": "${node.transport}",
                "path": "/"
            }
        }
        """.trimIndent()
    }
}
