package com.example.mandala.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.mandala.data.NodeRepository
import com.example.mandala.utils.NodeParser
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import mobile.Mobile

// 保持 Node 数据类定义不变
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

    // --- UI 状态 ---
    private val _isConnected = MutableStateFlow(false)
    val isConnected = _isConnected.asStateFlow()

    private val _logs = MutableStateFlow(listOf("[系统] 就绪"))
    val logs = _logs.asStateFlow()

    private val _nodes = MutableStateFlow<List<Node>>(emptyList())
    val nodes = _nodes.asStateFlow()

    private val _currentNode = MutableStateFlow(Node("未选择节点", "none", "0.0.0.0", 0))
    val currentNode = _currentNode.asStateFlow()

    // [新增] 用于通知 Activity 执行 VPN 操作的事件流
    sealed class VpnEvent {
        data class StartVpn(val configJson: String) : VpnEvent()
        object StopVpn : VpnEvent()
    }
    private val _vpnEventChannel = Channel<VpnEvent>()
    val vpnEvent = _vpnEventChannel.receiveAsFlow()

    init {
        loadData()
        // 检查服务是否已经在运行 (用于重启 App 后恢复状态)
        _isConnected.value = Mobile.isRunning()
    }

    private fun loadData() {
        viewModelScope.launch {
            val savedNodes = repository.loadNodes()
            _nodes.value = savedNodes
            if (savedNodes.isNotEmpty()) {
                _currentNode.value = savedNodes[0]
            }
        }
    }

    // --- 核心操作 ---

    fun toggleConnection() {
        if (_isConnected.value) {
            // 请求停止
            viewModelScope.launch {
                _vpnEventChannel.send(VpnEvent.StopVpn)
                // 乐观更新 UI
                _isConnected.value = false
                addLog("[系统] 正在停止...")
            }
        } else {
            if (_currentNode.value.protocol == "none") {
                addLog("[错误] 请先选择有效节点")
                return
            }
            // 请求启动 (将配置发给 Activity)
            viewModelScope.launch {
                val config = generateConfigJson(_currentNode.value)
                _vpnEventChannel.send(VpnEvent.StartVpn(config))
                addLog("[系统] 请求建立 VPN 连接...")
            }
        }
    }
    
    // 当 Service 启动成功后，Activity 可以调用此方法确认状态
    fun onVpnStarted() {
        _isConnected.value = true
        addLog("[核心] VPN 服务已启动")
    }

    fun selectNode(node: Node) {
        if (_isConnected.value) {
            // 切换节点前需停止
             viewModelScope.launch {
                _vpnEventChannel.send(VpnEvent.StopVpn)
                _isConnected.value = false
             }
        }
        _currentNode.value = node
        addLog("[系统] 切换到节点: ${node.tag}")
    }

    fun addNode(node: Node) {
        val currentList = _nodes.value.toMutableList()
        val index = currentList.indexOfFirst { it.tag == node.tag && it.server == node.server }
        if (index != -1) currentList[index] = node else currentList.add(0, node)
        updateListAndSave(currentList)
    }

    fun deleteNode(node: Node) {
        val currentList = _nodes.value.toMutableList()
        if (currentList.removeIf { it.tag == node.tag && it.server == node.server }) {
            updateListAndSave(currentList)
            if (_currentNode.value.tag == node.tag) {
                _currentNode.value = if (currentList.isNotEmpty()) currentList[0] else Node("未选择", "none", "", 0)
            }
        }
    }

    fun importFromText(text: String): Boolean {
        val node = NodeParser.parse(text)
        return if (node != null) { addNode(node); true } else false
    }

    private fun updateListAndSave(newList: List<Node>) {
        _nodes.value = newList
        viewModelScope.launch { repository.saveNodes(newList) }
    }

    private fun addLog(msg: String) {
        // ... (保持日志逻辑不变)
        val currentLogs = _logs.value.toMutableList()
        if (currentLogs.size > 100) currentLogs.removeAt(0)
        currentLogs.add(msg)
        _logs.value = currentLogs
    }

    private fun generateConfigJson(node: Node): String {
        // ... (保持 JSON 生成逻辑不变)
        return """
        {
            "tag": "${node.tag}",
            "type": "${node.protocol}",
            "server": "${node.server}",
            "server_port": ${node.port},
            "password": "${node.password}",
            "uuid": "${node.uuid}",
            "tls": { "enabled": true, "server_name": "${node.server}" },
            "transport": { "type": "${node.transport}", "path": "/" }
        }
        """.trimIndent()
    }
}
