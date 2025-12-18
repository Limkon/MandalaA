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
    val path: String = "/",    // 补全路径
    val sni: String = "",      // 补全 SNI
    val isSelected: Boolean = false
)

class MainViewModel(application: Application) : AndroidViewModel(application) {
    private val repository = NodeRepository(application)

    private val _isConnected = MutableStateFlow(false)
    val isConnected = _isConnected.asStateFlow()

    private val _logs = MutableStateFlow(listOf("[系统] 就绪"))
    val logs = _logs.asStateFlow()

    private val _nodes = MutableStateFlow<List<Node>>(emptyList())
    val nodes = _nodes.asStateFlow()

    private val _currentNode = MutableStateFlow(Node("未选择", "none", "0.0.0.0", 0))
    val currentNode = _currentNode.asStateFlow()

    sealed class VpnEvent {
        data class StartVpn(val configJson: String) : VpnEvent()
        object StopVpn : VpnEvent()
    }
    private val _vpnEventChannel = Channel<VpnEvent>()
    val vpnEvent = _vpnEventChannel.receiveAsFlow()

    init {
        loadData()
        _isConnected.value = Mobile.isRunning()
    }

    private fun loadData() {
        viewModelScope.launch {
            val savedNodes = repository.loadNodes()
            _nodes.value = savedNodes
            if (savedNodes.isNotEmpty()) _currentNode.value = savedNodes[0]
        }
    }

    fun toggleConnection() {
        viewModelScope.launch {
            if (_isConnected.value) {
                _vpnEventChannel.send(VpnEvent.StopVpn)
                _isConnected.value = false
                addLog("[系统] 正在停止...")
            } else {
                if (_currentNode.value.protocol == "none") {
                    addLog("[错误] 请选择节点")
                    return@launch
                }
                val config = generateConfigJson(_currentNode.value)
                _vpnEventChannel.send(VpnEvent.StartVpn(config))
                addLog("[系统] 建立连接中...")
            }
        }
    }

    fun onVpnStarted() { _isConnected.value = true; addLog("[核心] 已连接") }
    fun onVpnStopped() { _isConnected.value = false; addLog("[核心] 已断开") }

    fun selectNode(node: Node) {
        if (_isConnected.value) toggleConnection()
        _currentNode.value = node
        addLog("[系统] 切换: ${node.tag}")
    }

    private fun addLog(msg: String) {
        val current = _logs.value.toMutableList()
        if (current.size > 100) current.removeAt(0)
        current.add(msg)
        _logs.value = current
    }

    private fun generateConfigJson(node: Node): String {
        val useTls = node.protocol != "socks" && node.protocol != "shadowsocks"
        val sniValue = if (node.sni.isEmpty()) node.server else node.sni
        
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
                "server_name": "$sniValue",
                "insecure": true 
            },
            "transport": { 
                "type": "${node.transport}", 
                "path": "${node.path}" 
            }
        }
        """.trimIndent()
    }
}
