package com.example.mandala.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.mandala.data.NodeRepository
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import mobile.Mobile

data class Node(
    val tag: String,
    val protocol: String,
    val server: String,
    val port: Int,
    val password: String = "",
    val uuid: String = "",
    val transport: String = "tcp",
    val isSelected: Boolean = false
)

class MainViewModel(application: Application) : AndroidViewModel(application) {
    private val repository = NodeRepository(application)

    private val _isConnected = MutableStateFlow(false)
    val isConnected = _isConnected.asStateFlow()

    private val _nodes = MutableStateFlow<List<Node>>(emptyList())
    val nodes = _nodes.asStateFlow()

    private val _currentNode = MutableStateFlow(Node("未選擇", "none", "0.0.0.0", 0))
    val currentNode = _currentNode.asStateFlow()

    sealed class VpnEvent {
        data class StartVpn(val configJson: String) : VpnEvent()
        object StopVpn : VpnEvent()
    }
    private val _vpnEventChannel = Channel<VpnEvent>()
    val vpnEvent = _vpnEventChannel.receiveAsFlow()

    init {
        viewModelScope.launch {
            val saved = repository.loadNodes()
            _nodes.value = saved
            if (saved.isNotEmpty()) _currentNode.value = saved[0]
            _isConnected.value = Mobile.isRunning()
        }
    }

    fun toggleConnection() {
        viewModelScope.launch {
            if (_isConnected.value) {
                _vpnEventChannel.send(VpnEvent.StopVpn)
                _isConnected.value = false
            } else {
                if (_currentNode.value.protocol != "none") {
                    val json = generateConfigJson(_currentNode.value)
                    _vpnEventChannel.send(VpnEvent.StartVpn(json))
                    _isConnected.value = true
                }
            }
        }
    }

    fun selectNode(node: Node) {
        _currentNode.value = node
    }

    // [關鍵修復] 動態生成配置 JSON
    private fun generateConfigJson(node: Node): String {
        // 判斷是否需要啟用 TLS (一般 Trojan/Vless 默認開啟)
        val useTls = node.protocol != "socks" && node.protocol != "shadowsocks"
        
        return """
        {
            "tag": "${node.tag}",
            "type": "${node.protocol}",
            "server": "${node.server}",
            "server_port": ${node.port},
            "password": "${node.password}",
            "uuid": "${node.uuid}",
            "tls": { 
                "enabled": $useTls, 
                "server_name": "${node.server}",
                "insecure": true 
            },
            "transport": { 
                "type": "${node.transport}", 
                "path": "/" 
            }
        }
        """.trimIndent()
    }
}
