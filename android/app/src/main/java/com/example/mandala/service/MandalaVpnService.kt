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
import mobile.Mobile

class MandalaVpnService : VpnService() {
    companion object {
        const val ACTION_START = "com.example.mandala.service.START"
        const val ACTION_STOP = "com.example.mandala.service.STOP"
        const val EXTRA_CONFIG = "config_json"
        private const val VPN_ADDRESS = "172.16.0.1"
        private const val CHANNEL_ID = "MandalaChannel"
        private const val NOTIFICATION_ID = 1
    }

    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // [关键] 优先处理停止指令
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            // 明确告诉系统：服务停止后不要自动重启
            return START_NOT_STICKY
        }

        // 立即在前台显示通知，防止被杀
        startForeground(NOTIFICATION_ID, createNotification("正在连接..."))

        val config = intent?.getStringExtra(EXTRA_CONFIG) ?: ""
        
        // [修复] 如果配置为空（通常发生在系统自动尝试重启服务时），直接停止，不尝试启动
        if (config.isEmpty()) {
            stopVpn()
            return START_NOT_STICKY
        }

        startVpn(config)
        
        // [修复] 改为 START_NOT_STICKY，防止崩溃后无限自动重启
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
            .setSmallIcon(android.R.drawable.ic_menu_share) 
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun startVpn(configJson: String) {
        try {
            val builder = Builder()
                .addAddress(VPN_ADDRESS, 24)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .setMtu(1500)
                // 使用 8.8.8.8，Go 核心会拦截并走代理
                .addDnsServer("8.8.8.8")
                .addDisallowedApplication(packageName)
                .setSession("Mandala Core")

            vpnInterface = builder.establish()
            vpnInterface?.let {
                val manager = getSystemService(NotificationManager::class.java)
                manager.notify(NOTIFICATION_ID, createNotification("VPN 已连接"))

                // 启动 Go 核心
                val err = Mobile.startVpn(it.fd.toLong(), 1500L, configJson)
                if (err.isNotEmpty()) {
                    stopVpn()
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
            stopVpn()
        }
    }

    private fun stopVpn() {
        try {
            // 1. 先关闭 Go 核心
            Mobile.stop()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        
        try {
            // 2. 再关闭 Java 接口
            vpnInterface?.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        
        vpnInterface = null
        // 移除前台通知
        stopForeground(STOP_FOREGROUND_REMOVE)
        // 停止 Service 自身
        stopSelf()
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
