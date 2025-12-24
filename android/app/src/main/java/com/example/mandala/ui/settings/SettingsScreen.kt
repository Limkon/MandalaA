// 文件路径: android/app/src/main/java/com/example/mandala/ui/settings/SettingsScreen.kt

package com.example.mandala.ui.settings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.example.mandala.viewmodel.AppLanguage
import com.example.mandala.viewmodel.AppThemeMode
import com.example.mandala.viewmodel.MainViewModel

@Composable
fun SettingsScreen(viewModel: MainViewModel) {
    // 收集状态
    val strings by viewModel.appStrings.collectAsState()
    val vpnMode by viewModel.vpnMode.collectAsState()
    val allowInsecure by viewModel.allowInsecure.collectAsState()
    val tlsFragment by viewModel.tlsFragment.collectAsState()
    val randomPadding by viewModel.randomPadding.collectAsState()
    val localPort by viewModel.localPort.collectAsState()
    val loggingEnabled by viewModel.loggingEnabled.collectAsState() // [新增]
    val themeMode by viewModel.themeMode.collectAsState()
    val language by viewModel.language.collectAsState()

    // 端口编辑弹窗状态
    var showPortDialog by remember { mutableStateOf(false) }

    // 端口编辑逻辑
    if (showPortDialog) {
        var tempPort by remember { mutableStateOf(localPort.toString()) }
        var isError by remember { mutableStateOf(false) }

        AlertDialog(
            onDismissRequest = { showPortDialog = false },
            title = { Text(strings.localPort) },
            text = {
                Column {
                    OutlinedTextField(
                        value = tempPort,
                        onValueChange = { 
                            tempPort = it.filter { char -> char.isDigit() }
                            isError = false
                        },
                        label = { Text("Port (1024-65535)") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        isError = isError,
                        singleLine = true
                    )
                    if (isError) {
                        Text("无效端口", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val p = tempPort.toIntOrNull()
                    if (p != null && p in 1024..65535) {
                        viewModel.updateLocalPort(tempPort)
                        showPortDialog = false
                    } else {
                        isError = true
                    }
                }) { Text(strings.confirm) }
            },
            dismissButton = {
                TextButton(onClick = { showPortDialog = false }) { Text(strings.cancel) }
            }
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState())
    ) {
        Text(strings.settings, style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Spacer(modifier = Modifier.height(24.dp))

        // --- 连接设置 ---
        SettingSection(strings.connectionSettings) {
            SwitchSetting(
                title = strings.vpnMode,
                subtitle = strings.vpnModeDesc,
                checked = vpnMode,
                onCheckedChange = { viewModel.updateSetting("vpn_mode", it) }
            )
            SwitchSetting(
                title = strings.allowInsecure,
                subtitle = strings.allowInsecureDesc,
                checked = allowInsecure,
                onCheckedChange = { viewModel.updateSetting("allow_insecure", it) }
            )
        }

        // --- 协议参数 ---
        SettingSection(strings.protocolSettings) {
            SwitchSetting(
                title = strings.tlsFragment,
                subtitle = strings.tlsFragmentDesc,
                checked = tlsFragment,
                onCheckedChange = { viewModel.updateSetting("tls_fragment", it) }
            )
            SwitchSetting(
                title = strings.randomPadding,
                subtitle = strings.randomPaddingDesc,
                checked = randomPadding,
                onCheckedChange = { viewModel.updateSetting("random_padding", it) }
            )
            // [新增] 日志开关
            SwitchSetting(
                title = strings.enableLogging,
                subtitle = strings.enableLoggingDesc,
                checked = loggingEnabled,
                onCheckedChange = { viewModel.updateSetting("logging_enabled", it) }
            )
            // 可点击的端口设置
            ClickableSetting(
                title = strings.localPort,
                value = localPort.toString(),
                icon = Icons.Default.Edit,
                onClick = { showPortDialog = true }
            )
        }

        // --- 应用设置 (主题与语言) ---
        SettingSection(strings.appSettings) {
            // 主题选择
            DropdownSetting(
                title = strings.theme,
                currentValue = when(themeMode) {
                    AppThemeMode.SYSTEM -> "系统默认"
                    AppThemeMode.LIGHT -> "浅色"
                    AppThemeMode.DARK -> "深色"
                },
                options = listOf("系统默认", "浅色", "深色"),
                onOptionSelected = { index ->
                    viewModel.updateTheme(AppThemeMode.values()[index])
                }
            )

            // 语言选择
            DropdownSetting(
                title = strings.language,
                currentValue = when(language) {
                    AppLanguage.CHINESE -> "简体中文"
                    AppLanguage.ENGLISH -> "English"
                },
                options = listOf("简体中文", "English"),
                onOptionSelected = { index ->
                    viewModel.updateLanguage(AppLanguage.values()[index])
                }
            )
        }

        // --- 关于 ---
        SettingSection(strings.about) {
            Text(
                "Mandala Client v1.1.0",
                style = MaterialTheme.typography.bodyMedium,
                color = Color.Gray
            )
            Text(
                "Core: Go 1.23 / Gomobile",
                style = MaterialTheme.typography.bodyMedium,
                color = Color.Gray
            )
        }
    }
}

// --- 组件封装 ---

@Composable
fun SettingSection(title: String, content: @Composable ColumnScope.() -> Unit) {
    Text(
        title,
        color = MaterialTheme.colorScheme.primary,
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.Bold
    )
    Spacer(modifier = Modifier.height(8.dp))
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            content()
        }
    }
    Spacer(modifier = Modifier.height(24.dp))
}

@Composable
fun SwitchSetting(title: String, subtitle: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = Color.Gray)
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
fun ClickableSetting(title: String, value: String, icon: androidx.compose.ui.graphics.vector.ImageVector, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(title, style = MaterialTheme.typography.titleMedium)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(value, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Bold, color = Color.Gray)
            Spacer(modifier = Modifier.width(8.dp))
            Icon(icon, contentDescription = null, tint = Color.Gray, modifier = Modifier.size(20.dp))
        }
    }
}

@Composable
fun DropdownSetting(title: String, currentValue: String, options: List<String>, onOptionSelected: (Int) -> Unit) {
    var expanded by remember { mutableStateOf(false) }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { expanded = true }
            .padding(vertical = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(title, style = MaterialTheme.typography.titleMedium)
        
        Box {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(currentValue, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary)
                Icon(Icons.Default.ArrowDropDown, contentDescription = null)
            }
            DropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false }
            ) {
                options.forEachIndexed { index, label ->
                    DropdownMenuItem(
                        text = { Text(label) },
                        onClick = {
                            onOptionSelected(index)
                            expanded = false
                        }
                    )
                }
            }
        }
    }
}
