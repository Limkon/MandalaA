package com.example.mandala.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.example.mandala.MainActivity
import com.example.mandala.R
import mobile.Mobile // Gomobile 库

class MandalaVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.example.mandala.service.START"
        const val ACTION_STOP = "com.example.mandala.service.STOP"
        const val EXTRA_CONFIG = "config_json"
        
        // VPN 参数
        private const val VPN_ADDRESS = "172.16.0.1" // 虚拟网卡 IP
        private const val VPN_ROUTE = "0.0.0.0"      // 路由所有流量
        private const val CHANNEL_ID = "MandalaVpnChannel"
        private const val NOTIFICATION_ID = 1
    }

    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }

        // 启动前台通知 (必须在服务启动后 5秒内调用)
        startForeground(NOTIFICATION_ID, createNotification())

        val configJson = intent?.getStringExtra(EXTRA_CONFIG) ?: "{}"
        startVpn(configJson)

        return START_STICKY
    }

    private fun startVpn(configJson: String) {
        if (vpnInterface != null) return // 防止重复启动

        try {
            Log.d("MandalaVpn", "正在建立 VPN 接口...")
            
            // 1. 配置 Builder (搭建骨架)
            val builder = Builder()
                .setSession("Mandala")
                .addAddress(VPN_ADDRESS, 24)
                .addRoute(VPN_ROUTE, 0)
                .setMtu(1500)
            
            // [关键] 这一步会创建虚拟网卡，接管系统流量
            // 目前因为 Go 核心不支持 TUN，这些流量会被"丢弃"导致断网
            vpnInterface = builder.establish()

            Log.d("MandalaVpn", "VPN 接口建立成功. fd=${vpnInterface?.fd}")

            // 2. 启动 Go 核心 (SOCKS5 Server)
            // 虽然流量没通，但我们先把 Go 核心跑起来
            Log.d("MandalaVpn", "正在启动 Go 核心...")
            val err = Mobile.start(10809, configJson)
            if (err.isNotEmpty()) {
                Log.e("MandalaVpn", "Go 核心启动失败: $err")
                stopVpn()
            }

        } catch (e: Exception) {
            e.printStackTrace()
            stopVpn()
        }
    }

    private fun stopVpn() {
        try {
            // 停止 Go 核心
            Mobile.stop()
            
            // 关闭 VPN 接口
            vpnInterface?.close()
            vpnInterface = null
            
            stopForeground(true)
            stopSelf()
            Log.d("MandalaVpn", "VPN 服务已停止")
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    // --- 通知栏配置 ---
    private fun createNotification(): Notification {
        val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Mandala VPN Status",
                NotificationManager.IMPORTANCE_LOW
            )
            manager.createNotificationChannel(channel)
        }

        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Mandala VPN")
            .setContentText("正在保护您的网络连接")
            .setSmallIcon(R.mipmap.ic_launcher) // 确保图标存在
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }
}