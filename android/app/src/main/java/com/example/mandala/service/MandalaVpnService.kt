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
import mobile.Mobile

class MandalaVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.example.mandala.service.START"
        const val ACTION_STOP = "com.example.mandala.service.STOP"
        const val EXTRA_CONFIG = "config_json"
        
        private const val VPN_ADDRESS = "172.16.0.1"
        private const val VPN_MTU = 1500
        private const val CHANNEL_ID = "MandalaVpnChannel"
        private const val NOTIFICATION_ID = 1
    }

    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }

        startForeground(NOTIFICATION_ID, createNotification())
        val configJson = intent?.getStringExtra(EXTRA_CONFIG) ?: "{}"
        startVpn(configJson)

        return START_STICKY
    }

    private fun startVpn(configJson: String) {
        if (vpnInterface != null) return

        try {
            val builder = Builder()
                .setSession("Mandala")
                .addAddress(VPN_ADDRESS, 24)
                .addRoute("0.0.0.0", 0)  // IPv4 全局路由
                .addRoute("::", 0)       // [關鍵修復] IPv6 全局路由
                .setMtu(VPN_MTU)
                .addDnsServer("8.8.8.8")

            // 排除自身，防止流量死循環
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.e("MandalaVpn", "Exclude app failed", e)
            }

            vpnInterface = builder.establish()
            
            vpnInterface?.let {
                val err = Mobile.startVpn(it.fd.toInt(), VPN_MTU, configJson)
                if (err.isNotEmpty()) {
                    Log.e("MandalaVpn", "Go Core Error: $err")
                    stopVpn()
                }
            }
        } catch (e: Exception) {
            stopVpn()
        }
    }

    private fun stopVpn() {
        Mobile.stop()
        vpnInterface?.close()
        vpnInterface = null
        stopForeground(true)
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun createNotification(): Notification {
        val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "VPN Status", NotificationManager.IMPORTANCE_LOW)
            manager.createNotificationChannel(channel)
        }
        val intent = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Mandala VPN")
            .setContentText("服務運行中")
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentIntent(intent)
            .setOngoing(true)
            .build()
    }
}
