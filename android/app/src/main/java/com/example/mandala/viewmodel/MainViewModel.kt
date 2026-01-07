// 文件路径: android/app/src/main/java/com/example/mandala/viewmodel/MainViewModel.kt

package com.example.mandala.viewmodel

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.work.*
import com.example.mandala.data.NodeRepository
import com.example.mandala.utils.NodeParser
import com.example.mandala.worker.SubscriptionWorker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import mobile.Mobile
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.util.concurrent.TimeUnit

// --- 数据模型定义 ---

data class AppStrings(
    val home: String, val profiles: String, val settings: String,
    val connect: String, val disconnect: String,
    val connected: String, val notConnected: String,
    val noNodeSelected: String,
    val nodeManagement: String, val importFromClipboard: String, val clipboardEmpty: String,
    val connectionSettings: String,
    val vpnMode: String, val vpnModeDesc: String,
    val allowInsecure: String, val allowInsecureDesc: String,
    val protocolSettings: String,
    val tlsFragment: String, val tlsFragmentDesc: String,
    val randomPadding: String, val randomPaddingDesc: String,
    // [新增] ECH 相关文本
    val echSettings: String, val enableEch: String, val enableEchDesc: String,
    val echPublicName: String, val echDoH: String,
    
    val localPort: String,
    val enableLogging: String,
    val enableLoggingDesc: String,
    val appSettings: String, val theme: String, val language: String,
    val about: String, val confirm: String, val cancel: String,
    val edit: String, val delete: String, val save: String,
    val deleteConfirm: String,
    val tag: String, val address: String, val port: String,
    val password: String, val uuid: String, val sni: String,
    val subscription: String, val addSubscription: String, val editSubscription: String, val subUrl: String,
    val updateInterval: String, val daily: String, val weekly: String, val custom: String, 
    val intervalNever: String, // [新增] 从不更新选项
    val updateNow: String, val lastUpdate: String, val neverUpdate: String
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
    // [新增] ECH 中文
    echSettings = "ECH (加密 Client Hello)", enableEch = "启用 ECH", enableEchDesc = "加密握手信息，防止 SNI 嗅探",
    echPublicName = "公共名称 (Public Name)", echDoH = "DoH 服务器 (用于获取密钥)",
    
    localPort = "本地监听端口",
    enableLogging = "启用日志记录",
    enableLoggingDesc = "将核心运行日志保存到本地文件以便调试",
    appSettings = "应用设置", theme = "主题", language = "语言",
    about = "关于", confirm = "确定", cancel = "取消",
    edit = "编辑", delete = "删除", save = "保存",
    deleteConfirm = "确定要删除吗？",
    tag = "备注", address = "地址", port = "端口",
    password = "密码", uuid = "UUID", sni = "SNI (域名)",
    subscription = "订阅管理", addSubscription = "添加订阅", editSubscription = "编辑订阅", subUrl = "订阅地址 (URL)",
    updateInterval = "更新频率", daily = "每天", weekly = "每周", custom = "自定义天数", 
    intervalNever = "从不 (手动)", // [新增]
    updateNow = "立即更新", lastUpdate = "最后更新", neverUpdate = "从未更新"
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
    // [新增] ECH 英文
    echSettings = "ECH Settings", enableEch = "Enable ECH", enableEchDesc = "Encrypt handshake to hide SNI",
    echPublicName = "Public Name", echDoH = "DoH Server URL",
    
    localPort = "Local Port",
    enableLogging = "Enable Logging",
    enableLoggingDesc = "Save core logs to local file for debugging",
    appSettings = "App Settings", theme = "Theme", language = "Language",
    about = "About", confirm = "OK", cancel = "Cancel",
    edit = "Edit", delete = "Delete", save = "Save",
    deleteConfirm = "Are you sure you want to delete?",
    tag = "Tag", address = "Address", port = "Port",
    password = "Password", uuid = "UUID", sni = "SNI",
    subscription = "Subscriptions", addSubscription = "Add Sub", editSubscription = "Edit Sub", subUrl = "Subscription URL",
    updateInterval = "Update Interval", daily = "Daily", weekly = "Weekly", custom = "Custom Days",
    intervalNever = "Never (Manual)", // [新增]
    updateNow = "Update Now", lastUpdate = "Last update", neverUpdate = "Never"
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
    val isSelected: Boolean = false,
    val subscriptionUrl: String? = null 
)

// [修改] 添加 NEVER
enum class UpdateInterval { DAILY, WEEKLY, CUSTOM, NEVER }

data class Subscription(
    val url: String,
    val tag: String,
    val lastUpdated: Long = 0,
    val interval: UpdateInterval = UpdateInterval.DAILY,
    val customDays: Int = 1,
    val isEnabled: Boolean = true
)

enum class AppThemeMode { SYSTEM, LIGHT, DARK }
enum class AppLanguage { CHINESE, ENGLISH }

// --- ViewModel 实现 ---

class MainViewModel(application: Application) : AndroidViewModel(application) {
    private val repository = NodeRepository(application)
    private val prefs = application.getSharedPreferences("mandala_settings", Context.MODE_PRIVATE)
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    private val _isConnected = MutableStateFlow(false)
    val isConnected = _isConnected.asStateFlow()

    private val _logs = MutableStateFlow(listOf("[系统] 准备就绪"))
    val logs = _logs.asStateFlow()

    private val _nodes = MutableStateFlow<List<Node>>(emptyList())
    val nodes = _nodes.asStateFlow()

    private val _subscriptions = MutableStateFlow<List<Subscription>>(emptyList())
    val subscriptions = _subscriptions.asStateFlow()

    private val _currentNode = MutableStateFlow(Node("未选择", "none", "0.0.0.0", 0))
    val currentNode = _currentNode.asStateFlow()

    private val _vpnMode = MutableStateFlow(prefs.getBoolean("vpn_mode", true))
    val vpnMode = _vpnMode.asStateFlow()

    private val _allowInsecure = MutableStateFlow(prefs.getBoolean("allow_insecure", false))
    val allowInsecure = _allowInsecure.asStateFlow()

    private val _tlsFragment = MutableStateFlow(prefs.getBoolean("tls_fragment", true))
    val tlsFragment = _tlsFragment.asStateFlow()

    private val _randomPadding = MutableStateFlow(prefs.getBoolean("random_padding", false))
    val randomPadding = _randomPadding.asStateFlow()

    // [新增] ECH 状态
    private val _enableEch = MutableStateFlow(prefs.getBoolean("enable_ech", false))
    val enableEch = _enableEch.asStateFlow()

    private val _echPublicName = MutableStateFlow(prefs.getString("ech_public_name", "cloudflare-ech.com") ?: "")
    val echPublicName = _echPublicName.asStateFlow()

    private val _echDoH = MutableStateFlow(prefs.getString("ech_doh_url", "https://1.1.1.1/dns-query") ?: "")
    val echDoH = _echDoH.asStateFlow()

    private val _localPort = MutableStateFlow(prefs.getInt("local_port", 10809))
    val localPort = _localPort.asStateFlow()

    private val _loggingEnabled = MutableStateFlow(prefs.getBoolean("logging_enabled", false))
    val loggingEnabled = _loggingEnabled.asStateFlow()

    private val _themeMode = MutableStateFlow(
        AppThemeMode.values()[prefs.getInt("theme_mode", AppThemeMode.SYSTEM.ordinal)]
    )
    val themeMode = _themeMode.asStateFlow()

    private val _language = MutableStateFlow(
        AppLanguage.values()[prefs.getInt("app_language", AppLanguage.CHINESE.ordinal)]
    )
    val language = _language.asStateFlow()

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
        refreshSubscriptions()
        _isConnected.value = Mobile.isRunning()
    }

    // --- 设置与基础数据刷新 ---

    fun updateSetting(key: String, value: Boolean) {
        prefs.edit().putBoolean(key, value).apply()
        when (key) {
            "vpn_mode" -> _vpnMode.value = value
            "allow_insecure" -> _allowInsecure.value = value
            "tls_fragment" -> _tlsFragment.value = value
            "random_padding" -> _randomPadding.value = value
            "logging_enabled" -> _loggingEnabled.value = value
            "enable_ech" -> _enableEch.value = value // [新增]
        }
    }

    // [新增] 更新字符串类型的设置
    fun updateStringSetting(key: String, value: String) {
        prefs.edit().putString(key, value).apply()
        when (key) {
            "ech_public_name" -> _echPublicName.value = value
            "ech_doh_url" -> _echDoH.value = value
        }
    }

    fun updateLocalPort(port: String) {
        val p = port.toIntOrNull()
        if (p != null && p in 1024..65535) {
            prefs.edit().putInt("local_port", p).apply()
            _localPort.value = p
        }
    }

    fun updateTheme(mode: AppThemeMode) {
        prefs.edit().putInt("theme_mode", mode.ordinal).apply()
        _themeMode.value = mode
    }

    fun updateLanguage(lang: AppLanguage) {
        prefs.edit().putInt("app_language", lang.ordinal).apply()
        _language.value = lang
    }

    fun refreshNodes() {
        viewModelScope.launch {
            val saved = repository.loadNodes()
            _nodes.value = saved
            val lastSelected = saved.find { it.isSelected }
            if (lastSelected != null) {
                _currentNode.value = lastSelected
            } else if (saved.isNotEmpty() && _currentNode.value.protocol == "none") {
                _currentNode.value = saved[0]
            }
        }
    }

    fun refreshSubscriptions() {
        viewModelScope.launch {
            _subscriptions.value = repository.loadSubscriptions()
        }
    }

    // --- 订阅管理 ---

    fun addSubscription(sub: Subscription) {
        viewModelScope.launch {
            val current = _subscriptions.value.toMutableList()
            if (current.none { it.url == sub.url }) {
                current.add(sub)
                repository.saveSubscriptions(current)
                _subscriptions.value = current
                scheduleSubscriptionUpdate(sub)
                updateSubscriptionContent(sub)
            }
        }
    }

    fun updateSubscription(oldSub: Subscription, newSub: Subscription) {
        viewModelScope.launch {
            val current = _subscriptions.value.toMutableList()
            val index = current.indexOfFirst { it.url == oldSub.url }
            if (index != -1) {
                // 如果 URL 变更，处理关联节点和旧任务
                if (oldSub.url != newSub.url) {
                    WorkManager.getInstance(getApplication()).cancelUniqueWork(oldSub.url)
                    val currentNodes = _nodes.value.toMutableList()
                    var nodesChanged = false
                    currentNodes.forEachIndexed { i, node ->
                        if (node.subscriptionUrl == oldSub.url) {
                            currentNodes[i] = node.copy(subscriptionUrl = newSub.url)
                            nodesChanged = true
                        }
                    }
                    if (nodesChanged) {
                        repository.saveNodes(currentNodes)
                        _nodes.value = currentNodes
                    }
                }

                val updatedSub = newSub.copy(lastUpdated = oldSub.lastUpdated)
                current[index] = updatedSub
                repository.saveSubscriptions(current)
                _subscriptions.value = current
                scheduleSubscriptionUpdate(updatedSub)
                addLog("[订阅] 已更新: ${updatedSub.tag}")
            }
        }
    }

    fun deleteSubscription(sub: Subscription) {
        viewModelScope.launch {
            val current = _subscriptions.value.toMutableList()
            current.removeAll { it.url == sub.url }
            repository.saveSubscriptions(current)
            _subscriptions.value = current
            
            val currentNodes = _nodes.value.toMutableList()
            currentNodes.removeAll { it.subscriptionUrl == sub.url }
            repository.saveNodes(currentNodes)
            _nodes.value = currentNodes
            
            WorkManager.getInstance(getApplication()).cancelUniqueWork(sub.url)
            addLog("[订阅] 已移除: ${sub.tag}")
        }
    }

    fun updateSubscriptionContent(sub: Subscription) {
        viewModelScope.launch(Dispatchers.IO) {
            addLog("[订阅] 正在更新: ${sub.tag}...")
            try {
                val request = Request.Builder().url(sub.url).build()
                httpClient.newCall(request).execute().use { response ->
                    if (response.isSuccessful) {
                        val body = response.body?.string() ?: ""
                        val newNodes = NodeParser.parseList(body).map { 
                            it.copy(subscriptionUrl = sub.url) 
                        }
                        
                        withContext(Dispatchers.Main) {
                            val allNodes = _nodes.value.toMutableList()
                            allNodes.removeAll { it.subscriptionUrl == sub.url }
                            allNodes.addAll(newNodes)
                            repository.saveNodes(allNodes)
                            _nodes.value = allNodes
                            
                            val allSubs = _subscriptions.value.toMutableList()
                            val idx = allSubs.indexOfFirst { it.url == sub.url }
                            if (idx != -1) {
                                allSubs[idx] = allSubs[idx].copy(lastUpdated = System.currentTimeMillis())
                                repository.saveSubscriptions(allSubs)
                                _subscriptions.value = allSubs
                            }
                            addLog("[订阅] 更新成功，导入 ${newNodes.size} 个节点")
                        }
                    } else {
                        addLog("[错误] 订阅更新失败: ${response.code}")
                    }
                }
            } catch (e: Exception) {
                addLog("[错误] 网络请求异常: ${e.message}")
            }
        }
    }

    private fun scheduleSubscriptionUpdate(sub: Subscription) {
        // [新增] 如果选择了从不更新，则取消现有的定时任务
        if (sub.interval == UpdateInterval.NEVER) {
            WorkManager.getInstance(getApplication()).cancelUniqueWork(sub.url)
            addLog("[订阅] 已取消自动更新: ${sub.tag}")
            return
        }

        val intervalMinutes = when(sub.interval) {
            UpdateInterval.DAILY -> 24L * 60
            UpdateInterval.WEEKLY -> 7L * 24 * 60
            UpdateInterval.CUSTOM -> sub.customDays.toLong() * 24 * 60
            else -> 24L * 60 // Fallback
        }

        val workRequest = PeriodicWorkRequestBuilder<SubscriptionWorker>(
            intervalMinutes, TimeUnit.MINUTES,
            15, TimeUnit.MINUTES 
        ).addTag(sub.url)
         .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
         .build()

        WorkManager.getInstance(getApplication()).enqueueUniquePeriodicWork(
            sub.url,
            ExistingPeriodicWorkPolicy.UPDATE,
            workRequest
        )
    }

    // --- 节点管理与 VPN ---

    fun toggleConnection() {
        viewModelScope.launch {
            if (_isConnected.value) {
                _vpnEventChannel.send(VpnEvent.StopVpn)
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
        val wasConnected = _isConnected.value
        val updatedNode = node.copy(isSelected = true)
        _currentNode.value = updatedNode
        addLog("[系统] 已选择: ${node.tag}")

        viewModelScope.launch {
            val currentList = _nodes.value.map { 
                if (it.server == node.server && it.port == node.port && 
                    it.protocol == node.protocol && it.tag == node.tag) {
                    it.copy(isSelected = true)
                } else {
                    it.copy(isSelected = false)
                }
            }
            _nodes.value = currentList
            repository.saveNodes(currentList)

            if (wasConnected) {
                addLog("[系统] 检测到节点变更，正在自动重启服务...")
                _vpnEventChannel.send(VpnEvent.StopVpn)
                delay(800) 
                val json = generateConfigJson(updatedNode)
                _vpnEventChannel.send(VpnEvent.StartVpn(json))
            }
        }
    }

    fun addNode(node: Node) {
        viewModelScope.launch {
            val currentList = _nodes.value.toMutableList()
            val nodeToSave = if (currentList.isEmpty()) node.copy(isSelected = true) else node.copy(isSelected = false)
            currentList.add(nodeToSave)
            repository.saveNodes(currentList)
            _nodes.value = currentList
            if (currentList.size == 1) _currentNode.value = nodeToSave
            addLog("[系统] 已添加: ${node.tag}")
        }
    }

    fun deleteNode(node: Node) {
        viewModelScope.launch {
            val currentList = _nodes.value.toMutableList()
            currentList.remove(node)
            repository.saveNodes(currentList)
            if (_currentNode.value == node) {
                 if (currentList.isNotEmpty()) {
                     val nextNode = currentList[0].copy(isSelected = true)
                     _currentNode.value = nextNode
                     _nodes.value = currentList.mapIndexed { i, it -> it.copy(isSelected = (i == 0)) }
                 } else {
                     _currentNode.value = Node("未选择", "none", "0.0.0.0", 0)
                     _nodes.value = emptyList()
                 }
            } else { _nodes.value = currentList }
            addLog("[系统] 已删除: ${node.tag}")
        }
    }

    fun updateNode(oldNode: Node, newNode: Node) {
        viewModelScope.launch {
            val currentList = _nodes.value.toMutableList()
            val index = currentList.indexOf(oldNode)
            if (index != -1) {
                val nodeToSave = newNode.copy(isSelected = oldNode.isSelected)
                currentList[index] = nodeToSave
                repository.saveNodes(currentList)
                if (_currentNode.value == oldNode) _currentNode.value = nodeToSave
                _nodes.value = currentList
                addLog("[系统] 已更新: ${newNode.tag}")
            }
        }
    }

    fun onVpnStarted() { _isConnected.value = true; addLog("[核心] 已连通网络") }
    fun onVpnStopped() { _isConnected.value = false; addLog("[核心] 连接已关闭") }

    fun importFromText(text: String, onResult: (Boolean, String) -> Unit) {
        val newNodes = NodeParser.parseList(text)
        if (newNodes.isNotEmpty()) {
            viewModelScope.launch {
                val current = _nodes.value.toMutableList()
                var addedCount = 0
                for (node in newNodes) {
                    if (current.none { it.server == node.server && it.port == node.port && it.protocol == node.protocol }) {
                        current.add(node.copy(isSelected = false))
                        addedCount++
                    }
                }
                if (addedCount > 0) {
                    repository.saveNodes(current); refreshNodes()
                    addLog("[系统] 成功导入 $addedCount 个节点")
                    onResult(true, "导入成功")
                } else onResult(false, "节点已存在")
            }
        } else onResult(false, "未识别到节点")
    }

    fun addLog(msg: String) {
        val current = _logs.value.toMutableList()
        if (current.size > 100) current.removeAt(0)
        current.add(msg)
        _logs.value = current
    }

    private fun generateConfigJson(node: Node): String {
        val useTls = node.sni.isNotEmpty() || node.transport == "ws" || node.port == 443
        val logPath = if (_loggingEnabled.value) {
            val logDir = getApplication<Application>().getExternalFilesDir(null)
            if (logDir != null) File(logDir, "mandala_core.log").absolutePath 
            else getApplication<Application>().filesDir.absolutePath + "/mandala_core.log"
        } else ""
        
        // [修改] 注入 ECH 字段到 JSON
        return """
        {
            "tag": "${node.tag}",
            "type": "${node.protocol}",
            "server": "${node.server}",
            "server_port": ${node.port},
            "password": "${node.password}",
            "uuid": "${node.uuid}",
            "username": "${if(node.protocol == "socks5") node.uuid else ""}",
            "log_path": "$logPath",
            "tls": { 
                "enabled": $useTls, 
                "server_name": "${if (node.sni.isEmpty()) node.server else node.sni}", 
                "insecure": ${_allowInsecure.value},
                "enable_ech": ${_enableEch.value},
                "ech_public_name": "${_echPublicName.value}",
                "ech_doh_url": "${_echDoH.value}"
            },
            "transport": { "type": "${node.transport}", "path": "${node.path}" },
            "settings": { "vpn_mode": ${_vpnMode.value}, "fragment": ${_tlsFragment.value}, "noise": ${_randomPadding.value} },
            "local_port": ${_localPort.value}
        }
        """.trimIndent()
    }
}
