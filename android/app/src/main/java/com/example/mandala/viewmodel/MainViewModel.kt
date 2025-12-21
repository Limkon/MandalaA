package com.example.mandala.viewmodel

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.mandala.data.NodeRepository
import com.example.mandala.utils.NodeParser
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import mobile.Mobile

// [新增] 多语言字符串封装
data class AppStrings(
    val home: String,
    val profiles: String,
    val settings: String,
    val connect: String,
    val disconnect: String,
    val connected: String,
    val notConnected: String,
    val noNodeSelected: String,
    val nodeManagement: String,
    val importFromClipboard: String,
    val clipboardEmpty: String,
    val connectionSettings: String,
    val vpnMode: String,
    val vpnModeDesc: String,
    val allowInsecure: String,
    val allowInsecureDesc: String,
    val protocolSettings: String,
    val tlsFragment: String,
    val tlsFragmentDesc: String,
    val randomPadding: String,
    val randomPaddingDesc: String,
    val localPort: String,
    val appSettings: String,
    val theme: String,
    val language: String,
    val about: String,
    val confirm: String,
    val cancel: String
)

val ChineseStrings = AppStrings(
    home = "首页", profiles = "节点", settings = "设置",
    connect = "连接", disconnect = "断开",
    connected = "已连接", notConnected = "未连接",
    noNodeSelected = "请先选择一个节点",
    nodeManagement = "节点管理", importFromClipboard = "从剪贴板导入", clipboardEmpty = "剪贴板为空",
    connectionSettings = "连接设置",
    vpnMode = "VPN 模式", vpnModeDesc = "通过 Mandala 路由所有设备流量",
    allowInsecure = "允许不安全连接", allowInsecureDesc = "跳过 TLS 证书验证 (危险)",
    protocolSettings = "协议参数 (核心)",
    tlsFragment = "TLS 分片", tlsFragmentDesc = "拆分 TLS 记录以绕过 DPI 检测",
    randomPadding = "随机填充", randomPaddingDesc = "向数据包添加随机噪音",
    localPort = "本地监听端口",
    appSettings = "应用设置", theme = "主题", language = "语言",
    about = "关于", confirm = "确定", cancel = "取消"
)

val EnglishStrings = AppStrings(
    home = "Home", profiles = "Profiles", settings = "Settings",
    connect = "Connect", disconnect = "Disconnect",
    connected = "Connected", notConnected = "Disconnected",
    noNodeSelected = "Please select a node first",
    nodeManagement = "Profiles", importFromClipboard = "Import from Clipboard", clipboardEmpty = "Clipboard is empty",
    connectionSettings = "Connection",
    vpnMode = "VPN Mode", vpnModeDesc = "Route all traffic through Mandala",
    allowInsecure = "Insecure", allowInsecureDesc = "Skip TLS verification (Dangerous)",
    protocolSettings = "Protocol",
    tlsFragment = "TLS Fragment", tlsFragmentDesc = "Split TLS records to bypass DPI",
    randomPadding = "Random Padding", randomPaddingDesc = "Add random noise to packets",
    localPort = "Local Port",
    appSettings = "App Settings", theme = "Theme", language = "Language",
    about = "About", confirm = "OK", cancel = "Cancel"
)

data class Node(
    val tag: String,
    val protocol: String,
    val server: String,
    val port: Int,
    val password: String = "",
    val uuid: String = "",
    val transport: String = "tcp",
    val path: String = "/",
    val sni: String = "",
    val isSelected: Boolean = false
)

// 主题枚举
enum class AppThemeMode { SYSTEM, LIGHT, DARK }
// 语言枚举
enum class AppLanguage { CHINESE, ENGLISH }

class MainViewModel(application: Application) : AndroidViewModel(application) {
    private val repository = NodeRepository(application)
    private val prefs = application.getSharedPreferences("mandala_settings", Context.MODE_PRIVATE)

    private val _isConnected = MutableStateFlow(false)
    val isConnected = _isConnected.asStateFlow()

    private val _logs = MutableStateFlow(listOf("[系统] 准备就绪"))
    val logs = _logs.asStateFlow()

    private val _nodes = MutableStateFlow<List<Node>>(emptyList())
    val nodes = _nodes.asStateFlow()

    private val _currentNode = MutableStateFlow(Node("未选择", "none", "0.0.0.0", 0))
    val currentNode = _currentNode.asStateFlow()

    // 设置状态
    private val _vpnMode = MutableStateFlow(prefs.getBoolean("vpn_mode", true))
    val vpnMode = _vpnMode.asStateFlow()

    private val _allowInsecure = MutableStateFlow(prefs.getBoolean("allow_insecure", false))
    val allowInsecure = _allowInsecure.asStateFlow()

    private val _tlsFragment = MutableStateFlow(prefs.getBoolean("tls_fragment", true))
    val tlsFragment = _tlsFragment.asStateFlow()

    private val _randomPadding = MutableStateFlow(prefs.getBoolean("random_padding", false))
    val randomPadding = _randomPadding.asStateFlow()

    // [新增] 本地端口
    private val _localPort = MutableStateFlow(prefs.getInt("local_port", 10809))
    val localPort = _localPort.asStateFlow()

    // [新增] 主题
    private val _themeMode = MutableStateFlow(
        AppThemeMode.values()[prefs.getInt("theme_mode", AppThemeMode.SYSTEM.ordinal)]
    )
    val themeMode = _themeMode.asStateFlow()

    // [新增] 语言
    private val _language = MutableStateFlow(
        AppLanguage.values()[prefs.getInt("app_language", AppLanguage.CHINESE.ordinal)]
    )
    val language = _language.asStateFlow()

    // [新增] 当前语言字符串流
    val appStrings = _language.map { 
        if (it == AppLanguage.ENGLISH) EnglishStrings else ChineseStrings 
    }.stateIn(viewModelScope, SharingStarted.Eagerly, ChineseStrings)

    sealed class VpnEvent {
        data class StartVpn(val configJson: String) : VpnEvent()
        object StopVpn : VpnEvent()
    }
    private val _vpnEventChannel = Channel<VpnEvent>()
    val vpnEvent = _vpnEventChannel.receiveAsFlow()

    init {
        refreshNodes()
        _isConnected.value = Mobile.isRunning()
    }

    // 更新 Boolean 设置
    fun updateSetting(key: String, value: Boolean) {
        prefs.edit().putBoolean(key, value).apply()
        when (key) {
            "vpn_mode" -> _vpnMode.value = value
            "allow_insecure" -> _allowInsecure.value = value
            "tls_fragment" -> _tlsFragment.value = value
            "random_padding" -> _randomPadding.value = value
        }
    }

    // [新增] 更新端口设置
    fun updateLocalPort(port: String) {
        val p = port.toIntOrNull()
        if (p != null && p in 1024..65535) {
            prefs.edit().putInt("local_port", p).apply()
            _localPort.value = p
        }
    }

    // [新增] 更新主题
    fun updateTheme(mode: AppThemeMode) {
        prefs.edit().putInt("theme_mode", mode.ordinal).apply()
        _themeMode.value = mode
    }

    // [新增] 更新语言
    fun updateLanguage(lang: AppLanguage) {
        prefs.edit().putInt("app_language", lang.ordinal).apply()
        _language.value = lang
    }

    fun refreshNodes() {
        viewModelScope.launch {
            val saved = repository.loadNodes()
            _nodes.value = saved
            if (saved.isNotEmpty() && _currentNode.value.protocol == "none") {
                _currentNode.value = saved[0]
            }
        }
    }

    fun toggleConnection() {
        viewModelScope.launch {
            if (_isConnected.value) {
                _vpnEventChannel.send(VpnEvent.StopVpn)
                // 状态不立即改变，等待 Service 通知
                addLog("[系统] 正在断开...")
            } else {
                if (_currentNode.value.protocol != "none") {
                    val json = generateConfigJson(_currentNode.value)
                    _vpnEventChannel.send(VpnEvent.StartVpn(json))
                    addLog("[系统] 正在连接: ${_currentNode.value.tag}")
                } else {
                    addLog("[错误] ${appStrings.value.noNodeSelected}")
                }
            }
        }
    }

    fun selectNode(node: Node) {
        _currentNode.value = node
        addLog("[系统] 已选择: ${node.tag}")
    }

    fun onVpnStarted() {
        _isConnected.value = true
        addLog("[核心] 已连通网络")
    }

    fun onVpnStopped() {
        _isConnected.value = false
        addLog("[核心] 连接已关闭")
    }

    fun importFromText(text: String, onResult: (Boolean, String) -> Unit) {
        val node = NodeParser.parse(text)
        if (node != null) {
            viewModelScope.launch {
                val current = _nodes.value.toMutableList()
                if (current.any { it.server == node.server && it.port == node.port }) {
                    onResult(false, "节点已存在")
                    return@launch
                }
                current.add(node)
                repository.saveNodes(current)
                refreshNodes()
                addLog("[系统] 导入成功: ${node.tag}")
                onResult(true, "导入成功")
            }
        } else {
            onResult(false, "无效的链接格式")
        }
    }

    fun addLog(msg: String) {
        val current = _logs.value.toMutableList()
        if (current.size > 100) current.removeAt(0)
        current.add(msg)
        _logs.value = current
    }

    private fun generateConfigJson(node: Node): String {
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
                "server_name": "${if (node.sni.isEmpty()) node.server else node.sni}",
                "insecure": ${_allowInsecure.value}
            },
            "transport": { "type": "${node.transport}", "path": "${node.path}" },
            "settings": {
                "vpn_mode": ${_vpnMode.value},
                "fragment": ${_tlsFragment.value},
                "noise": ${_randomPadding.value}
            },
            "local_port": ${_localPort.value}
        }
        """.trimIndent()
    }
}
