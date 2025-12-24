// 文件路径: android/app/src/main/java/com/example/mandala/ui/home/HomeScreen.kt

package com.example.mandala.ui.home

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.mandala.viewmodel.MainViewModel

@Composable
fun HomeScreen(viewModel: MainViewModel) {
    val isConnected by viewModel.isConnected.collectAsState()
    val currentNode by viewModel.currentNode.collectAsState()
    val logs by viewModel.logs.collectAsState()
    val strings by viewModel.appStrings.collectAsState()

    // 已移除动画相关的 rememberInfiniteTransition 和 angle 变量以节省开销

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // --- 顶部栏 ---
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "Mandala",
                fontSize = 28.sp, 
                fontWeight = FontWeight.Bold, 
                color = MaterialTheme.colorScheme.primary
            )
            IconButton(onClick = { /* TODO: 扫码 */ }) {
                Icon(Icons.Default.QrCodeScanner, contentDescription = "Scan")
            }
        }

        Spacer(modifier = Modifier.height(32.dp))

        // --- 状态卡片 ---
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            shape = RoundedCornerShape(16.dp)
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Text("Current Node", style = MaterialTheme.typography.labelSmall, color = Color.Gray)
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    currentNode.tag, 
                    style = MaterialTheme.typography.titleLarge, 
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        if (isConnected) strings.connected else strings.notConnected,
                        color = if (isConnected) Color(0xFF4CAF50) else Color.Gray,
                        fontWeight = FontWeight.Bold
                    )
                    Text(currentNode.protocol.uppercase(), style = MaterialTheme.typography.labelMedium)
                }
            }
        }

        Spacer(modifier = Modifier.weight(1f))

        // --- 连接按钮 ---
        Box(contentAlignment = Alignment.Center) {
            // 已移除原本在 isConnected 为 true 时显示的旋转渐变背景 Box 层

            Button(
                onClick = { viewModel.toggleConnection() },
                modifier = Modifier.size(140.dp),
                shape = CircleShape,
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (isConnected) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
                ),
                elevation = ButtonDefaults.buttonElevation(8.dp)
            ) {
                Icon(
                    Icons.Default.PowerSettingsNew,
                    contentDescription = if (isConnected) strings.disconnect else strings.connect,
                    modifier = Modifier.size(64.dp).scale(1.2f)
                )
            }
        }

        Spacer(modifier = Modifier.weight(1f))

        // --- 日志预览 ---
        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .height(120.dp),
            shape = RoundedCornerShape(12.dp),
            color = MaterialTheme.colorScheme.surface.copy(alpha = 0.5f),
            border = androidx.compose.foundation.BorderStroke(1.dp, Color.Gray.copy(alpha = 0.2f))
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text("System Logs", style = MaterialTheme.typography.labelSmall, color = Color.Gray)
                Spacer(modifier = Modifier.height(8.dp))
                logs.takeLast(4).forEach { log ->
                    Text(
                        log, 
                        style = MaterialTheme.typography.bodySmall, 
                        maxLines = 1,
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
                    )
                }
            }
        }
    }
}
