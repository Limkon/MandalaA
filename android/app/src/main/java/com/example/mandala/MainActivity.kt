package com.example.mandala

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.example.mandala.service.MandalaVpnService
import com.example.mandala.ui.home.HomeScreen
import com.example.mandala.ui.profiles.ProfilesScreen
import com.example.mandala.ui.settings.SettingsScreen
import com.example.mandala.ui.theme.MandalaTheme
import com.example.mandala.viewmodel.AppThemeMode
import com.example.mandala.viewmodel.MainViewModel
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private var pendingConfigJson: String? = null
    private lateinit var vpnStateReceiver: BroadcastReceiver

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            pendingConfigJson?.let { startVpnService(it) }
        } else {
            Toast.makeText(this, "需要 VPN 权限才能连接", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // 获取 ViewModel 实例 (用于在 Receiver 中调用)
        val viewModel = androidx.lifecycle.ViewModelProvider(this)[MainViewModel::class.java]

        // [修复] 初始化广播接收器，监听 Service 真正停止的事件
        vpnStateReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                if (intent?.action == MandalaVpnService.ACTION_VPN_STOPPED) {
                    viewModel.onVpnStopped()
                }
            }
        }
        
        // 注册广播
        val filter = IntentFilter(MandalaVpnService.ACTION_VPN_STOPPED)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(vpnStateReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(vpnStateReceiver, filter)
        }
        
        setContent {
            // [新增] 监听主题设置
            val themeMode by viewModel.themeMode.collectAsState()
            val isDarkTheme = when (themeMode) {
                AppThemeMode.LIGHT -> false
                AppThemeMode.DARK -> true
                else -> isSystemInDarkTheme() // SYSTEM
            }

            MandalaTheme(darkTheme = isDarkTheme) {
                // 监听 VPN 启动/停止指令
                LaunchedEffect(Unit) {
                    lifecycleScope.launch {
                        repeatOnLifecycle(Lifecycle.State.STARTED) {
                            viewModel.vpnEvent.collect { event ->
                                when (event) {
                                    is MainViewModel.VpnEvent.StartVpn -> prepareAndStartVpn(event.configJson)
                                    is MainViewModel.VpnEvent.StopVpn -> stopVpnService()
                                }
                            }
                        }
                    }
                }

                MainApp(viewModel)
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // [修复] 注销广播，防止泄漏
        try {
            unregisterReceiver(vpnStateReceiver)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun prepareAndStartVpn(configJson: String) {
        pendingConfigJson = configJson
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startVpnService(configJson)
        }
    }

    private fun startVpnService(configJson: String) {
        val intent = Intent(this, MandalaVpnService::class.java).apply {
            action = MandalaVpnService.ACTION_START
            putExtra(MandalaVpnService.EXTRA_CONFIG, configJson)
        }
        startForegroundService(intent)
        
        val viewModel = androidx.lifecycle.ViewModelProvider(this)[MainViewModel::class.java]
        viewModel.onVpnStarted()
    }

    private fun stopVpnService() {
        val intent = Intent(this, MandalaVpnService::class.java).apply {
            action = MandalaVpnService.ACTION_STOP
        }
        startService(intent)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainApp(viewModel: MainViewModel) {
    val navController = rememberNavController()
    // [新增] 监听多语言字符串
    val strings by viewModel.appStrings.collectAsState()
    
    val navItems = listOf(
        Triple(strings.home, "Home", Icons.Filled.Home),
        Triple(strings.profiles, "Profiles", Icons.Filled.List),
        Triple(strings.settings, "Settings", Icons.Filled.Settings)
    )

    Scaffold(
        bottomBar = {
            NavigationBar {
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentRoute = navBackStackEntry?.destination?.route

                navItems.forEach { (label, route, icon) ->
                    NavigationBarItem(
                        icon = { Icon(icon, contentDescription = label) },
                        label = { Text(label) },
                        selected = currentRoute == route,
                        onClick = {
                            navController.navigate(route) {
                                popUpTo(navController.graph.startDestinationId) {
                                    saveState = true
                                }
                                launchSingleTop = true
                                restoreState = true
                            }
                        }
                    )
                }
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = "Home",
            modifier = Modifier.padding(innerPadding)
        ) {
            composable("Home") { HomeScreen(viewModel) }
            composable("Profiles") { ProfilesScreen(viewModel) }
            composable("Settings") { SettingsScreen(viewModel) }
        }
    }
}
