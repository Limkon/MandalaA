// 文件路径: android/app/src/main/java/com/example/mandala/service/MandalaVpnService.kt

package com.example.mandala.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.example.mandala.MainActivity
import com.example.mandala.R
import mobile.Mobile
import java.io.IOException

class MandalaVpnService : VpnService() {
    companion object {
        const val ACTION_START = "com.example.mandala.service.START"
        const val ACTION_STOP = "com.example.mandala.service.STOP"
        const val ACTION_VPN_STOPPED = "com.example.mandala.service.VPN_STOPPED"
        
        const val EXTRA_CONFIG = "config_json"
        private const val VPN_ADDRESS = "172.16.0.1"
        private const val CHANNEL_ID = "MandalaChannel"
        private const val NOTIFICATION_ID = 1
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    // [修复] 增加运行状态标记，防止重复启动或停止
    private var isRunning = false

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }

        // 提升前台服务优先级
        startForeground(NOTIFICATION_ID, createNotification("正在连接..."))

        val config = intent?.getStringExtra(EXTRA_CONFIG) ?: ""
        if (config.isEmpty()) {
            stopVpn()
            return START_NOT_STICKY
        }

        startVpn(config)
        return START_NOT_STICKY
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Mandala VPN 状态",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "显示 VPN 连接状态"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(content: String): android.app.Notification {
        val pendingIntent = Intent(this, MainActivity::class.java).let {
            PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE)
        }

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Mandala VPN")
            .setContentText(content)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true) // [优化] 防止状态更新时通知震动打扰
            .build()
    }

    private fun startVpn(configJson: String) {
        if (isRunning) return
        isRunning = true

        try {
            // [优化] 如果之前有未关闭的接口，先关闭，防止 FD 泄露
            if (vpnInterface != null) {
                try { vpnInterface?.close() } catch (e: Exception) {}
                vpnInterface = null
            }

            val builder = Builder()
                .addAddress(VPN_ADDRESS, 24)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .setMtu(1500)
                .addDnsServer("8.8.8.8")
                .addDisallowedApplication(packageName)
                .setSession("Mandala Core")
            
            // Android 10+ 建议显式设置按流量计费状态
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            vpnInterface = builder.establish()
            
            // 检查建立是否成功（如被其他 VPN 抢占）
            val fd = vpnInterface?.fd
            if (fd == null) {
                stopVpn()
                return
            }

            val manager = getSystemService(NotificationManager::class.java)
            manager.notify(NOTIFICATION_ID, createNotification("VPN 已连接"))

            // 启动 Go 核心
            // 注意：fd 必须转换为 Long 传递
            val err = Mobile.startVpn(fd.toLong(), 1500L, configJson)
            if (err.isNotEmpty()) {
                android.util.Log.e("MandalaVpn", "Core start failed: $err")
                stopVpn()
            }
        } catch (e: Exception) {
            e.printStackTrace()
            stopVpn()
        }
    }

    private fun stopVpn() {
        isRunning = false
        
        try {
            // [修复] 确保 Mobile.stop() 被调用
            Mobile.stop()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        
        try {
            // [修复] 必须关闭文件描述符，否则下次启动可能会失败或内存泄露
            vpnInterface?.close()
        } catch (e: IOException) {
            e.printStackTrace()
        } finally {
            vpnInterface = null
        }
        
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()

        // 发送广播通知 UI 更新
        sendBroadcast(Intent(ACTION_VPN_STOPPED).setPackage(packageName))
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }
}
