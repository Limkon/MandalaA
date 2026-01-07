// 文件路径: android/app/src/main/java/com/example/mandala/ui/profiles/ProfilesScreen.kt

package com.example.mandala.ui.profiles

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.example.mandala.viewmodel.*
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfilesScreen(viewModel: MainViewModel) {
    val nodes by viewModel.nodes.collectAsState()
    val strings by viewModel.appStrings.collectAsState()
    
    var showNodeEditDialog by remember { mutableStateOf(false) }
    var showSubManageDialog by remember { mutableStateOf(false) }
    var currentNode by remember { mutableStateOf<Node?>(null) }
    
    val clipboardManager = LocalClipboardManager.current
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        floatingActionButton = {
            Column(
                horizontalAlignment = Alignment.End,
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // 订阅管理入口
                SmallFloatingActionButton(
                    onClick = { showSubManageDialog = true },
                    containerColor = MaterialTheme.colorScheme.tertiaryContainer
                ) {
                    Icon(Icons.Default.RssFeed, contentDescription = "Subscriptions")
                }

                // 剪贴板导入
                SmallFloatingActionButton(
                    onClick = {
                        val clipData = clipboardManager.getText()
                        if (!clipData.isNullOrBlank()) {
                            viewModel.importFromText(clipData.text) { _, msg ->
                                scope.launch { snackbarHostState.showSnackbar(msg) }
                            }
                        } else {
                            scope.launch { snackbarHostState.showSnackbar(strings.clipboardEmpty) }
                        }
                    },
                    containerColor = MaterialTheme.colorScheme.secondaryContainer
                ) {
                    Icon(Icons.Default.ContentPaste, contentDescription = "Import")
                }

                // 添加节点
                FloatingActionButton(onClick = {
                    currentNode = null
                    showNodeEditDialog = true
                }) {
                    Icon(Icons.Default.Add, contentDescription = "Add Node")
                }
            }
        }
    ) { padding ->
        if (nodes.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Text("暂无节点，请点击右下角导入或添加", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        } else {
            LazyColumn(modifier = Modifier.fillMaxSize().padding(padding)) {
                items(nodes) { node ->
                    NodeItem(
                        node = node,
                        onEdit = { currentNode = node; showNodeEditDialog = true },
                        onDelete = { viewModel.deleteNode(node) },
                        onSelect = { viewModel.selectNode(node) }
                    )
                }
            }
        }
    }

    // 节点编辑弹窗
    if (showNodeEditDialog) {
        NodeEditDialog(
            node = currentNode,
            onDismiss = { showNodeEditDialog = false },
            onSave = { newNode ->
                if (currentNode == null) viewModel.addNode(newNode)
                else viewModel.updateNode(currentNode!!, newNode)
                showNodeEditDialog = false
            }
        )
    }

    // 订阅管理弹窗
    if (showSubManageDialog) {
        SubscriptionManagementDialog(
            viewModel = viewModel,
            onDismiss = { showSubManageDialog = false }
        )
    }
}

@Composable
fun NodeItem(node: Node, onEdit: () -> Unit, onDelete: () -> Unit, onSelect: () -> Unit) {
    val cardColors = if (node.isSelected) CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer) else CardDefaults.cardColors()
    Card(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp).clickable { onSelect() },
        elevation = CardDefaults.cardElevation(2.dp),
        colors = cardColors
    ) {
        Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(text = node.tag, style = MaterialTheme.typography.titleMedium)
                    if (node.isSelected) {
                        Spacer(modifier = Modifier.width(8.dp))
                        Icon(Icons.Default.CheckCircle, null, modifier = Modifier.size(16.dp), tint = MaterialTheme.colorScheme.primary)
                    }
                    if (node.subscriptionUrl != null) {
                        Spacer(modifier = Modifier.width(8.dp))
                        Icon(Icons.Default.CloudDownload, null, modifier = Modifier.size(14.dp), tint = MaterialTheme.colorScheme.outline)
                    }
                }
                Text(text = "${node.protocol.uppercase()} | ${node.server}:${node.port}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            IconButton(onClick = onEdit) { Icon(Icons.Default.Edit, "Edit") }
            IconButton(onClick = onDelete) { Icon(Icons.Default.Delete, "Delete") }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SubscriptionManagementDialog(viewModel: MainViewModel, onDismiss: () -> Unit) {
    val subs by viewModel.subscriptions.collectAsState()
    val strings by viewModel.appStrings.collectAsState()
    var showEditSubDialog by remember { mutableStateOf(false) }
    var currentSub by remember { mutableStateOf<Subscription?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(strings.subscription) },
        text = {
            Column(modifier = Modifier.fillMaxWidth().heightIn(max = 400.dp)) {
                if (subs.isEmpty()) {
                    Text("尚未添加任何订阅", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(16.dp))
                } else {
                    LazyColumn {
                        items(subs) { sub ->
                            SubscriptionItem(
                                sub = sub, 
                                strings = strings,
                                onUpdate = { viewModel.updateSubscriptionContent(sub) },
                                onEdit = { currentSub = sub; showEditSubDialog = true },
                                onDelete = { viewModel.deleteSubscription(sub) }
                            )
                        }
                    }
                }
                TextButton(
                    onClick = { currentSub = null; showEditSubDialog = true },
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
                ) {
                    Icon(Icons.Default.Add, null)
                    Spacer(Modifier.width(8.dp))
                    Text(strings.addSubscription)
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(strings.confirm) } }
    )

    if (showEditSubDialog) {
        SubscriptionEditDialog(
            subscription = currentSub,
            strings = strings,
            onDismiss = { showEditSubDialog = false },
            onSave = { tag, url, interval, customDays ->
                val newSub = Subscription(url, tag, interval = interval, customDays = customDays)
                if (currentSub == null) {
                    viewModel.addSubscription(newSub)
                } else {
                    viewModel.updateSubscription(currentSub!!, newSub)
                }
                showEditSubDialog = false
            }
        )
    }
}

@Composable
fun SubscriptionItem(
    sub: Subscription, 
    strings: AppStrings, 
    onUpdate: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit
) {
    val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault())
    val lastUpdateStr = if (sub.lastUpdated == 0L) strings.neverUpdate else sdf.format(Date(sub.lastUpdated))

    Card(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(sub.tag, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                IconButton(onClick = onUpdate, modifier = Modifier.size(24.dp)) {
                    Icon(Icons.Default.Refresh, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(18.dp))
                }
                Spacer(Modifier.width(8.dp))
                IconButton(onClick = onEdit, modifier = Modifier.size(24.dp)) {
                    Icon(Icons.Default.Edit, null, tint = MaterialTheme.colorScheme.secondary, modifier = Modifier.size(18.dp))
                }
                Spacer(Modifier.width(8.dp))
                IconButton(onClick = onDelete, modifier = Modifier.size(24.dp)) {
                    Icon(Icons.Default.Delete, null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(18.dp))
                }
            }
            Text(sub.url, style = MaterialTheme.typography.labelSmall, maxLines = 1, color = MaterialTheme.colorScheme.outline)
            Spacer(Modifier.height(4.dp))
            Text("${strings.lastUpdate}: $lastUpdateStr", style = MaterialTheme.typography.labelSmall)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SubscriptionEditDialog(
    subscription: Subscription?,
    strings: AppStrings, 
    onDismiss: () -> Unit, 
    onSave: (String, String, UpdateInterval, Int) -> Unit
) {
    var tag by remember { mutableStateOf(subscription?.tag ?: "") }
    var url by remember { mutableStateOf(subscription?.url ?: "") }
    var interval by remember { mutableStateOf(subscription?.interval ?: UpdateInterval.DAILY) }
    var customDays by remember { mutableStateOf(subscription?.customDays?.toString() ?: "1") }
    var expandedInterval by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (subscription == null) strings.addSubscription else strings.editSubscription) },
        text = {
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                OutlinedTextField(value = tag, onValueChange = { tag = it }, label = { Text(strings.tag) }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(value = url, onValueChange = { url = it }, label = { Text(strings.subUrl) }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                Spacer(Modifier.height(16.dp))
                
                ExposedDropdownMenuBox(expanded = expandedInterval, onExpandedChange = { expandedInterval = !expandedInterval }) {
                    OutlinedTextField(
                        value = when(interval) {
                            UpdateInterval.DAILY -> strings.daily
                            UpdateInterval.WEEKLY -> strings.weekly
                            UpdateInterval.CUSTOM -> strings.custom
                            UpdateInterval.NEVER -> strings.intervalNever // [新增]
                        },
                        onValueChange = {}, readOnly = true, label = { Text(strings.updateInterval) },
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expandedInterval) },
                        modifier = Modifier.menuAnchor().fillMaxWidth()
                    )
                    ExposedDropdownMenu(expanded = expandedInterval, onDismissRequest = { expandedInterval = false }) {
                        DropdownMenuItem(text = { Text(strings.daily) }, onClick = { interval = UpdateInterval.DAILY; expandedInterval = false })
                        DropdownMenuItem(text = { Text(strings.weekly) }, onClick = { interval = UpdateInterval.WEEKLY; expandedInterval = false })
                        DropdownMenuItem(text = { Text(strings.custom) }, onClick = { interval = UpdateInterval.CUSTOM; expandedInterval = false })
                        // [新增]
                        DropdownMenuItem(text = { Text(strings.intervalNever) }, onClick = { interval = UpdateInterval.NEVER; expandedInterval = false })
                    }
                }

                if (interval == UpdateInterval.CUSTOM) {
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = customDays, 
                        onValueChange = { customDays = it.filter { c -> c.isDigit() } }, 
                        label = { Text("天数") }, 
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }
            }
        },
        confirmButton = { Button(onClick = { onSave(tag, url, interval, customDays.toIntOrNull() ?: 1) }) { Text(strings.save) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(strings.cancel) } }
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodeEditDialog(node: Node?, onDismiss: () -> Unit, onSave: (Node) -> Unit) {
    var tag by remember { mutableStateOf(node?.tag ?: "新节点") }
    var protocol by remember { mutableStateOf(node?.protocol ?: "vless") }
    var server by remember { mutableStateOf(node?.server ?: "") }
    var port by remember { mutableStateOf(node?.port?.toString() ?: "443") }
    var password by remember { mutableStateOf(node?.password ?: "") }
    var uuid by remember { mutableStateOf(node?.uuid ?: "") }
    var transport by remember { mutableStateOf(node?.transport ?: "tcp") }
    var sni by remember { mutableStateOf(node?.sni ?: "") }
    var path by remember { mutableStateOf(node?.path ?: "/") }
    var showAdvanced by remember { mutableStateOf(false) }
    var expandedProtocol by remember { mutableStateOf(false) }

    val protocols = listOf("vless", "trojan", "shadowsocks", "socks5", "mandala")
    val transports = listOf("tcp", "ws")

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(text = if (node == null) "添加节点" else "编辑节点") },
        text = {
            Column(modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState())) {
                OutlinedTextField(value = tag, onValueChange = { tag = it }, label = { Text("备注 (Tag)") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                Spacer(modifier = Modifier.height(8.dp))
                ExposedDropdownMenuBox(expanded = expandedProtocol, onExpandedChange = { expandedProtocol = !expandedProtocol }, modifier = Modifier.fillMaxWidth()) {
                    OutlinedTextField(value = protocol.uppercase(), onValueChange = {}, readOnly = true, label = { Text("协议类型") },
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expandedProtocol) }, modifier = Modifier.menuAnchor().fillMaxWidth())
                    ExposedDropdownMenu(expanded = expandedProtocol, onDismissRequest = { expandedProtocol = false }) {
                        protocols.forEach { p -> DropdownMenuItem(text = { Text(p.uppercase()) }, onClick = { protocol = p; expandedProtocol = false }) }
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
                Row(modifier = Modifier.fillMaxWidth()) {
                    OutlinedTextField(value = server, onValueChange = { server = it }, label = { Text("地址") }, modifier = Modifier.weight(0.65f), singleLine = true)
                    Spacer(modifier = Modifier.width(8.dp))
                    OutlinedTextField(value = port, onValueChange = { port = it }, label = { Text("端口") }, modifier = Modifier.weight(0.35f), singleLine = true)
                }
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(value = uuid, onValueChange = { uuid = it }, label = { Text("UUID/用户名") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(value = password, onValueChange = { password = it }, label = { Text("密码") }, visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth(), singleLine = true)
                TextButton(onClick = { showAdvanced = !showAdvanced }) { Text(if (showAdvanced) "收起高级" else "展开高级 (WS/TLS)") }
                if (showAdvanced) {
                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Row { transports.forEach { t -> FilterChip(selected = (transport == t), onClick = { transport = t }, label = { Text(t.uppercase()) }, modifier = Modifier.padding(end = 8.dp)) } }
                            if (transport == "ws") OutlinedTextField(value = path, onValueChange = { path = it }, label = { Text("WS 路径") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                            Spacer(Modifier.height(8.dp))
                            OutlinedTextField(value = sni, onValueChange = { sni = it }, label = { Text("SNI") }, placeholder = { Text("Host") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                        }
                    }
                }
            }
        },
        confirmButton = { Button(onClick = { onSave(Node(tag, protocol, server, port.toIntOrNull() ?: 443, password, uuid, transport, path, sni)) }) { Text("保存") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } }
    )
}
