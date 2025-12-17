// 文件路径: android/app/src/main/java/com/example/mandala/service/MandalaVpnService.kt

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
        private const val VPN_MTU = 1500
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

        // 必须在 5 秒内调用 startForeground
        startForeground(NOTIFICATION_ID, createNotification())

        val configJson = intent?.getStringExtra(EXTRA_CONFIG) ?: "{}"
        if (action == ACTION_START) {
            startVpn(configJson)
        }

        return START_STICKY
    }

    private fun startVpn(configJson: String) {
        if (vpnInterface != null) return

        try {
            Log.d("MandalaVpn", "1. 正在建立 VPN 接口...")
            
            // --- 步骤 A: 创建 Android 虚拟网卡 ---
            val builder = Builder()
                .setSession("Mandala")
                .addAddress(VPN_ADDRESS, 24)
                .addRoute(VPN_ROUTE, 0)
                .setMtu(VPN_MTU)
                // 建议: 添加 DNS 服务器，防止 DNS 泄露或无法解析
                .addDnsServer("8.8.8.8") 
                .addDnsServer("1.1.1.1")

            // 只有应用在前台或拥有 VPN 权限时才能调用
            vpnInterface = builder.establish()

            if (vpnInterface == null) {
                Log.e("MandalaVpn", "VPN 接口建立失败 (权限不足或被抢占)")
                stopSelf()
                return
            }

            // 获取文件描述符 (File Descriptor)
            // Go 核心将通过这个 FD 直接读取/写入网络数据包
            val fd = vpnInterface!!.fd
            Log.d("MandalaVpn", "VPN 接口建立成功. fd=$fd")

            // --- 步骤 B: 启动 Go 核心 (tun2socks 模式) ---
            Log.d("MandalaVpn", "2. 正在启动 Go 核心...")
            
            // 注意: Mobile.startVpn 是我们在 lib.go 中新加的函数
            // 参数: fd (int), mtu (int), config (json string)
            // Gomobile 可能会将 Go 的 int 映射为 Java 的 long，如果编译报错请尝试 fd.toLong()
            val err = Mobile.startVpn(fd, VPN_MTU, configJson)
            
            if (err.isNotEmpty()) {
                Log.e("MandalaVpn", "Go 核心启动失败: $err")
                stopVpn()
            } else {
                Log.d("MandalaVpn", "Go 核心启动成功，服务运行中")
            }

        } catch (e: Exception) {
            Log.e("MandalaVpn", "启动异常", e)
            stopVpn()
        }
    }

    private fun stopVpn() {
        try {
            Log.d("MandalaVpn", "正在停止服务...")
            
            // 1. 停止 Go 核心
            Mobile.stop()
            
            // 2. 关闭文件描述符 (这会自动销毁 VPN 接口)
            vpnInterface?.close()
            vpnInterface = null
            
            stopForeground(true)
            stopSelf()
            Log.d("MandalaVpn", "服务已停止")
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        // 当用户在系统设置里手动断开 VPN 时触发
        stopVpn()
        super.onRevoke()
    }

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
            .setContentText("安全连接已建立")
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentIntent(pendingIntent)
            .setOngoing(true) // 禁止用户侧滑删除
            .build()
    }
}
