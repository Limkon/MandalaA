// 文件路径: android/app/src/main/java/com/example/mandala/utils/NodeParser.kt

package com.example.mandala.utils

import android.net.Uri
import android.util.Base64
import com.example.mandala.viewmodel.Node
import com.google.gson.Gson
import com.google.gson.JsonObject
import java.nio.charset.StandardCharsets

object NodeParser {
    
    // [新增] 批量解析方法
    fun parseList(text: String): List<Node> {
        val nodes = mutableListOf<Node>()
        // 使用正则按空白字符（换行、空格、制表符）分割
        val lines = text.split("\\s+".toRegex())
        
        for (line in lines) {
            if (line.isNotBlank()) {
                // 尝试解析每一行
                parse(line)?.let { nodes.add(it) }
            }
        }
        return nodes
    }

    fun parse(link: String): Node? {
        val trimmed = link.trim().replace("\n", "").replace("\r", "")
        return try {
            when {
                trimmed.startsWith("mandala://", ignoreCase = true) -> parseMandala(trimmed)
                trimmed.startsWith("vmess://", ignoreCase = true) -> parseVmess(trimmed)
                trimmed.startsWith("vless://", ignoreCase = true) -> parseVless(trimmed)
                trimmed.startsWith("trojan://", ignoreCase = true) -> parseTrojan(trimmed)
                trimmed.startsWith("ss://", ignoreCase = true) -> parseShadowsocks(trimmed)
                // [修复] 同时支持 socks5:// 和 socks:// (兼容通用格式)
                trimmed.startsWith("socks5://", ignoreCase = true) -> parseSocks5(trimmed)
                trimmed.startsWith("socks://", ignoreCase = true) -> parseSocks5(trimmed)
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun parseMandala(link: String): Node? {
        val uri = Uri.parse(link)
        val host = uri.host ?: return null
        
        return Node(
            tag = uri.fragment?.let { Uri.decode(it) } ?: "未命名Mandala",
            protocol = "mandala",
            server = host,
            port = if (uri.port > 0) uri.port else 443,
            password = uri.userInfo?.let { Uri.decode(it) } ?: "",
            transport = if (uri.getQueryParameter("type") == "ws") "ws" else "tcp",
            path = uri.getQueryParameter("path")?.let { Uri.decode(it) } ?: "/",
            sni = uri.getQueryParameter("sni") ?: ""
        )
    }

    private fun parseVmess(link: String): Node? {
        var base64Part = link.substring(8).trim()
        if (base64Part.contains("?")) {
            base64Part = base64Part.substringBefore("?")
        }

        val decodedBytes = try {
            Base64.decode(base64Part, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        } catch (e: Exception) {
            try {
                Base64.decode(base64Part, Base64.DEFAULT)
            } catch (e2: Exception) {
                return null
            }
        }

        val jsonStr = String(decodedBytes, StandardCharsets.UTF_8)
        val json = Gson().fromJson(jsonStr, JsonObject::class.java)

        val portElement = json.get("port")
        val port = when {
            portElement == null -> 443
            portElement.isJsonPrimitive && portElement.asJsonPrimitive.isNumber -> portElement.asInt
            else -> portElement.asString.toIntOrNull() ?: 443
        }

        return Node(
            tag = json.get("ps")?.asString?.let { Uri.decode(it) } ?: "未命名VMess",
            protocol = "vless", // 注意：VMess 在此项目中映射为 Vless 处理
            server = json.get("add")?.asString ?: return null,
            port = port,
            uuid = json.get("id")?.asString ?: "",
            transport = if (json.get("net")?.asString == "ws") "ws" else "tcp",
            path = json.get("path")?.asString ?: "/",
            sni = json.get("sni")?.asString ?: ""
        )
    }

    private fun parseTrojan(link: String): Node? {
        val uri = Uri.parse(link)
        return Node(
            tag = uri.fragment?.let { Uri.decode(it) } ?: "未命名Trojan",
            protocol = "trojan",
            server = uri.host ?: return null,
            port = if (uri.port > 0) uri.port else 443,
            password = uri.userInfo?.let { Uri.decode(it) } ?: "",
            transport = if (uri.getQueryParameter("type") == "ws") "ws" else "tcp",
            path = uri.getQueryParameter("path") ?: "/",
            sni = uri.getQueryParameter("sni") ?: ""
        )
    }

    private fun parseVless(link: String): Node? {
        val uri = Uri.parse(link)
        return Node(
            tag = uri.fragment?.let { Uri.decode(it) } ?: "未命名VLESS",
            protocol = "vless",
            server = uri.host ?: return null,
            port = if (uri.port > 0) uri.port else 443,
            uuid = uri.userInfo?.let { Uri.decode(it) } ?: "",
            transport = if (uri.getQueryParameter("type") == "ws") "ws" else "tcp",
            path = uri.getQueryParameter("path") ?: "/",
            sni = uri.getQueryParameter("sni") ?: ""
        )
    }

    // [修复] 解析 Shadowsocks 链接 (参考 C 语言 ParseSSPlugin 逻辑)
    // 增加对 plugin 参数的解析，以支持 v2ray-plugin (WebSocket) 等场景
    private fun parseShadowsocks(link: String): Node? {
        var cleanLink = link
        var tag = "未命名SS"

        // 提取 Tag (#后面的内容)
        if (link.contains("#")) {
            tag = Uri.decode(link.substringAfterLast("#"))
            cleanLink = link.substringBeforeLast("#")
        }

        var uri = Uri.parse(cleanLink)
        var host = uri.host
        var port = uri.port
        var userInfo = uri.userInfo ?: ""

        // 如果 host 为空，尝试处理 ss://BASE64 格式
        if (host.isNullOrEmpty()) {
            // [Fix] 移除 ss:// 前缀后，仅取 ? 之前的部分进行解码，避免 query 参数干扰 Base64
            val base64Full = cleanLink.removePrefix("ss://")
            val base64Clean = if (base64Full.contains("?")) base64Full.substringBefore("?") else base64Full
            
            try {
                val decoded = String(Base64.decode(base64Clean, Base64.URL_SAFE or Base64.NO_WRAP), StandardCharsets.UTF_8)
                // 重新构造 URI 解析
                // 注意：如果原链接包含 plugin 参数 (SIP002)，它通常在 base64 之后，需要保留
                val queryPart = if (base64Full.contains("?")) "?" + base64Full.substringAfter("?") else ""
                uri = Uri.parse("ss://$decoded$queryPart")
                
                host = uri.host
                port = uri.port
                userInfo = uri.userInfo ?: ""
            } catch (e: Exception) {
                return null
            }
        }

        if (host.isNullOrEmpty()) return null

        // 处理用户信息 (method:password)
        var method = ""
        var password = ""

        if (userInfo.isNotEmpty()) {
            if (!userInfo.contains(":")) {
                try {
                    val decodedInfo = String(Base64.decode(userInfo, Base64.URL_SAFE or Base64.NO_WRAP), StandardCharsets.UTF_8)
                    userInfo = decodedInfo
                } catch (e: Exception) { }
            }

            if (userInfo.contains(":")) {
                method = userInfo.substringBefore(":")
                password = userInfo.substringAfter(":")
            } else {
                password = userInfo
            }
        }

        // [修复] 解析 Plugin 参数 (如 v2ray-plugin, obfs)
        val plugin = uri.getQueryParameter("plugin")
        val paramSni = uri.getQueryParameter("sni") // 优先使用链接自带的 sni
        
        var transport = "tcp"
        var finalSni = paramSni ?: ""
        var finalPath = "/"
        
        if (!plugin.isNullOrEmpty()) {
            // Plugin 格式通常为: v2ray-plugin;mode=websocket;host=Example.com;path=/ws;tls
            // 需要 URL Decode 确保分号等符号正确
            val decodedPlugin = Uri.decode(plugin)
            val parts = decodedPlugin.split(";")
            
            var pluginMode = ""
            var pluginHost = ""
            var pluginPath = ""
            // var pluginTls = false 
            
            for (part in parts) {
                val p = part.trim()
                when {
                    p.startsWith("mode=") -> pluginMode = p.substringAfter("mode=")
                    p.startsWith("host=") -> pluginHost = p.substringAfter("host=")
                    p.startsWith("obfs-host=") -> pluginHost = p.substringAfter("obfs-host=")
                    p.startsWith("path=") -> pluginPath = p.substringAfter("path=")
                    // p == "tls" || p.endsWith("=tls") -> pluginTls = true
                }
            }
            
            // 如果是 WebSocket 模式
            if (pluginMode.equals("websocket", ignoreCase = true) || 
                pluginMode.equals("ws", ignoreCase = true) || 
                decodedPlugin.contains("v2ray-plugin")) {
                
                transport = "ws"
                if (pluginPath.isNotEmpty()) finalPath = pluginPath
                // 如果 plugin 中指定了 host，通常用于 WS 的 Host Header 和 SNI
                if (pluginHost.isNotEmpty()) finalSni = pluginHost
            }
        }

        return Node(
            tag = tag,
            protocol = "shadowsocks",
            server = host!!,
            port = if (port > 0) port else 8388,
            password = Uri.decode(password),
            uuid = Uri.decode(method), // Method 存入 uuid
            transport = transport,     // [Fix] 正确设置传输方式 (ws/tcp)
            path = finalPath,          // [Fix] 正确设置路径
            sni = finalSni             // [Fix] 正确设置 SNI
        )
    }

    // [修复] 解析 Socks5 链接
    // 支持 socks:// 和 socks5://，并解析 ws/tls 参数
    private fun parseSocks5(link: String): Node? {
        val uri = Uri.parse(link)
        val host = uri.host ?: return null
        val userInfo = uri.userInfo ?: ""
        
        var username = ""
        var password = ""

        if (userInfo.isNotEmpty()) {
            if (userInfo.contains(":")) {
                username = userInfo.substringBefore(":")
                password = userInfo.substringAfter(":")
            } else {
                username = userInfo
            }
        }
        
        // [修复] 获取 URL 参数
        val type = uri.getQueryParameter("type")
        val path = uri.getQueryParameter("path")
        val sni = uri.getQueryParameter("sni")
        
        val transport = if (type == "ws") "ws" else "tcp"
        val finalPath = path ?: "/"
        val finalSni = sni ?: ""

        return Node(
            tag = uri.fragment?.let { Uri.decode(it) } ?: "未命名Socks5",
            protocol = "socks5",
            server = host,
            port = if (uri.port > 0) uri.port else 1080,
            password = Uri.decode(password), 
            uuid = Uri.decode(username),     
            transport = transport,           // [Fix] 支持 ws 传输
            path = finalPath,                // [Fix] 支持 path
            sni = finalSni                   // [Fix] 支持 sni
        )
    }
}
