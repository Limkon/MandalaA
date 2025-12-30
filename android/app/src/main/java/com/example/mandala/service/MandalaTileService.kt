// 文件路径: android/app/src/main/java/com/example/mandala/service/MandalaTileService.kt

package com.example.mandala.service

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.widget.Toast
import androidx.annotation.RequiresApi
import com.example.mandala.MainActivity
import com.example.mandala.data.NodeRepository
import com.example.mandala.viewmodel.Node
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import mobile.Mobile
import java.io.File

@RequiresApi(Build.VERSION_CODES.N)
class MandalaTileService : TileService() {

    // 下拉通知栏看到图标时调用，刷新状态
    override fun onStartListening() {
        super.onStartListening()
        updateTileState()
    }

    override fun onClick() {
        super.onClick()
        
        // 如果设备处于锁定状态，先请求解锁
        if (isLocked) {
            unlockAndRun { handleTileClick() }
        } else {
            handleTileClick()
        }
    }

    private fun handleTileClick() {
        // 1. 获取当前 VPN 核心运行状态
        val isRunning = try { Mobile.isRunning() } catch (e: Exception) { false }

        if (isRunning) {
            // --- 正在运行，执行关闭逻辑 ---
            val intent = Intent(this, MandalaVpnService::class.java).apply {
                action = MandalaVpnService.ACTION_STOP
            }
            startService(intent) // 发送停止指令
            
            // 立即更新 UI 为关闭状态，给用户反馈
            qsTile.state = Tile.STATE_INACTIVE
            qsTile.label = "Mandala (已关闭)"
            qsTile.updateTile()
            
            Toast.makeText(this, "正在断开 VPN...", Toast.LENGTH_SHORT).show()
        } else {
            // --- 未运行，执行开启逻辑 ---
            
            // [关键修复] 检查是否具有 VPN 权限
            // 如果 prepare 返回 null，说明有权限；如果不为 null，说明权限被撤销（如通过系统通知断开后）
            val prepareIntent = VpnService.prepare(this)
            
            if (prepareIntent != null) {
                // 没有权限，必须打开 App 让系统弹出授权对话框
                val intent = Intent(this, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                }
                startActivityAndCollapse(intent)
                Toast.makeText(this, "需要重新授权，请在 App 中连接", Toast.LENGTH_LONG).show()
            } else {
                // 有权限，直接在后台启动
                qsTile.state = Tile.STATE_UNAVAILABLE // 设置为中间状态
                qsTile.updateTile()
                Toast.makeText(this, "正在启动 VPN...", Toast.LENGTH_SHORT).show()
                startVpnBackground()
            }
        }
    }

    private fun updateTileState() {
        val tile = qsTile ?: return
        val isRunning = try { Mobile.isRunning() } catch (e: Exception) { false }
        
        // 根据状态设置图标颜色：Active(高亮), Inactive(灰色)
        tile.state = if (isRunning) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = if (isRunning) "Mandala (运行中)" else "Mandala"
        tile.updateTile()
    }

    private fun startVpnBackground() {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                // 1. 读取节点配置
                val repository = NodeRepository(applicationContext)
                val nodes = repository.loadNodes()
                val targetNode = nodes.find { it.isSelected } ?: nodes.firstOrNull()

                if (targetNode == null) {
                    withContext(Dispatchers.Main) {
                        Toast.makeText(applicationContext, "没有可用节点，请先添加", Toast.LENGTH_SHORT).show()
                        updateTileState()
                    }
                    return@launch
                }

                // 2. 读取全局设置并生成 JSON
                val prefs = getSharedPreferences("mandala_settings", Context.MODE_PRIVATE)
                val configJson = generateConfigJson(targetNode, prefs)

                // 3. 启动 VPN Service
                val intent = Intent(applicationContext, MandalaVpnService::class.java).apply {
                    action = MandalaVpnService.ACTION_START
                    putExtra(MandalaVpnService.EXTRA_CONFIG, configJson)
                }
                
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    startForegroundService(intent)
                } else {
                    startService(intent)
                }
                
                // 4. 更新 UI 为活跃状态
                withContext(Dispatchers.Main) {
                    qsTile.state = Tile.STATE_ACTIVE
                    qsTile.label = "Mandala (运行中)"
                    qsTile.updateTile()
                }

            } catch (e: Exception) {
                e.printStackTrace()
                withContext(Dispatchers.Main) {
                    Toast.makeText(applicationContext, "启动失败: ${e.message}", Toast.LENGTH_SHORT).show()
                    updateTileState()
                }
            }
        }
    }

    // JSON 生成逻辑（保持与 MainViewModel 一致）
    private fun generateConfigJson(node: Node, prefs: android.content.SharedPreferences): String {
        val vpnMode = prefs.getBoolean("vpn_mode", true)
        val allowInsecure = prefs.getBoolean("allow_insecure", false)
        val tlsFragment = prefs.getBoolean("tls_fragment", true)
        val randomPadding = prefs.getBoolean("random_padding", false)
        val localPort = prefs.getInt("local_port", 10809)
        val loggingEnabled = prefs.getBoolean("logging_enabled", false)

        val useTls = node.sni.isNotEmpty() || node.transport == "ws" || node.port == 443
        val logPath = if (loggingEnabled) {
             val logDir = getExternalFilesDir(null)
             if (logDir != null) File(logDir, "mandala_core.log").absolutePath 
             else filesDir.absolutePath + "/mandala_core.log"
        } else ""

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
            "tls": { "enabled": $useTls, "server_name": "${if (node.sni.isEmpty()) node.server else node.sni}", "insecure": $allowInsecure },
            "transport": { "type": "${node.transport}", "path": "${node.path}" },
            "settings": { "vpn_mode": $vpnMode, "fragment": $tlsFragment, "noise": $randomPadding },
            "local_port": $localPort
        }
        """.trimIndent()
    }
}
