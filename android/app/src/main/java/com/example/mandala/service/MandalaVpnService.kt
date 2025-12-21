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
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }

        // 1. 立即启动前台通知，防止系统杀掉进程
        startForeground(NOTIFICATION_ID, createNotification("正在连接..."))

        val config = intent?.getStringExtra(EXTRA_CONFIG) ?: ""
        if (config.isNotEmpty()) {
            startVpn(config)
        }
        
        return START_STICKY
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
            // 如果你有自定义图标，请替换下面的 android.R.drawable.ic_menu_share
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
                // [关键修改] 使用 Google DNS，确保流量被标准路由
                // Go 核心会拦截这个 IP 的 53 端口流量，并重定向到代理
                .addDnsServer("8.8.8.8")
                .addDisallowedApplication(packageName)
                .setSession("Mandala Core")

            vpnInterface = builder.establish()
            vpnInterface?.let {
                // 更新通知状态为已连接
                val manager = getSystemService(NotificationManager::class.java)
                manager.notify(NOTIFICATION_ID, createNotification("VPN 已连接"))

                // 传入 FD 给 Go 核心
                // 注意：这里 it.fd 是 Int，Go 接口可能定义为 Long，需要转换
                val err = Mobile.startVpn(it.fd.toLong(), 1500L, configJson)
                if (err.isNotEmpty()) {
                    // 如果 Go 核心启动失败，记录日志或停止 VPN
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
            Mobile.stop() // 调用 Go 核心停止
        } catch (e: Exception) {
            e.printStackTrace()
        }
        
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
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
