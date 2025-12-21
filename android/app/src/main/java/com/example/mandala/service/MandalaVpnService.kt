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
        const val ACTION_VPN_STOPPED = "com.example.mandala.service.VPN_STOPPED"
        
        const val EXTRA_CONFIG = "config_json"
        private const val VPN_ADDRESS = "172.16.0.1"
        private const val CHANNEL_ID = "MandalaChannel"
        private const val NOTIFICATION_ID = 1
        // [修改] 設置 MTU 為 1400，解決 TLS/WS 封裝導致的傳輸效率低下問題
        private const val VPN_MTU = 1400 
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
                .setMtu(VPN_MTU) // 使用優化後的 MTU
                .addDnsServer("8.8.8.8")
                .addDisallowedApplication(packageName)
                .setSession("Mandala Core")

            vpnInterface = builder.establish()
            vpnInterface?.let {
                val manager = getSystemService(NotificationManager::class.java)
                manager.notify(NOTIFICATION_ID, createNotification("VPN 已连接"))

                // 將當前 MTU 同步傳遞給 Go 核心堆棧
                val err = Mobile.startVpn(it.fd.toLong(), VPN_MTU.toLong(), configJson)
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
            Mobile.stop()
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
