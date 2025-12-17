package com.example.mandala.ui.profiles

import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.SignalCellularAlt
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.mandala.viewmodel.MainViewModel
import com.example.mandala.viewmodel.Node

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfilesScreen(viewModel: MainViewModel) {
    val nodes by viewModel.nodes.collectAsState()
    val currentNode by viewModel.currentNode.collectAsState()
    val context = LocalContext.current

    // 控制添加菜单的显示状态
    var showAddMenu by remember { mutableStateOf(false) }

    Scaffold(
        floatingActionButton = {
            Column(horizontalAlignment = Alignment.End) {
                // 当菜单展开时显示的额外选项：粘贴导入
                if (showAddMenu) {
                    SmallFloatingActionButton(
                        onClick = {
                            importFromClipboard(context, viewModel)
                            showAddMenu = false
                        },
                        containerColor = MaterialTheme.colorScheme.secondaryContainer,
                        modifier = Modifier.padding(bottom = 8.dp)
                    ) {
                        Icon(Icons.Default.ContentPaste, contentDescription = "粘贴导入")
                    }
                }

                // 主悬浮按钮
                FloatingActionButton(
                    onClick = {
                        // 切换菜单显示
                        showAddMenu = !showAddMenu
                        // 如果觉得操作繁琐，也可以改成单击直接导入，长按显示菜单
                        // 这里逻辑是：点击展开 -> 点击上面的粘贴图标 -> 导入
                    },
                    containerColor = MaterialTheme.colorScheme.primary
                ) {
                    Icon(
                        imageVector = if (showAddMenu) Icons.Default.Add else Icons.Default.Add, // 可以在展开时变X图标
                        contentDescription = "添加节点"
                    )
                }
            }
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .padding(16.dp)
                .fillMaxSize()
        ) {
            Text(
                "节点列表",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(16.dp))

            LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                items(nodes) { node ->
                    NodeItem(
                        node = node,
                        isSelected = (node.tag == currentNode.tag),
                        onClick = { viewModel.selectNode(node) }
                    )
                }
            }
        }
    }
}

// 辅助函数：处理剪贴板导入
private fun importFromClipboard(context: Context, viewModel: MainViewModel) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val clipData = clipboard.primaryClip

    if (clipData != null && clipData.itemCount > 0) {
        val text = clipData.getItemAt(0).text.toString()
        if (text.isNotBlank()) {
            val success = viewModel.importFromText(text)
            if (success) {
                Toast.makeText(context, "导入成功", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(context, "不支持的链接格式或解析失败", Toast.LENGTH_SHORT).show()
            }
        } else {
            Toast.makeText(context, "剪贴板为空", Toast.LENGTH_SHORT).show()
        }
    } else {
        Toast.makeText(context, "无法读取剪贴板", Toast.LENGTH_SHORT).show()
    }
}

@Composable
fun NodeItem(node: Node, isSelected: Boolean, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = if (isSelected)
                MaterialTheme.colorScheme.primaryContainer
            else
                MaterialTheme.colorScheme.surface
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // 协议图标
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .background(
                        if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.secondaryContainer,
                        shape = CircleShape
                    ),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    node.protocol.take(1).uppercase(),
                    color = if (isSelected) Color.White else MaterialTheme.colorScheme.onSecondaryContainer,
                    fontWeight = FontWeight.Bold
                )
            }

            Spacer(modifier = Modifier.width(16.dp))

            // 节点信息
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    node.tag,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    "${node.server}:${node.port}",
                    style = MaterialTheme.typography.bodySmall,
                    color = Color.Gray
                )
            }

            // 右侧状态
            if (isSelected) {
                Icon(
                    Icons.Default.CheckCircle,
                    contentDescription = "已选择",
                    tint = MaterialTheme.colorScheme.primary
                )
            } else {
                Icon(
                    Icons.Default.SignalCellularAlt,
                    contentDescription = "测速",
                    tint = Color.Gray
                )
            }

            IconButton(onClick = { /* TODO: 编辑菜单 */ }) {
                Icon(Icons.Default.MoreVert, contentDescription = "更多", tint = Color.Gray)
            }
        }
    }
}
