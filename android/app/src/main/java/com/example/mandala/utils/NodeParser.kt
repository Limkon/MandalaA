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
        // 这里的 replace 会移除行内的换行符，对于单行链接是安全的
        val trimmed = link.trim().replace("\n", "").replace("\r", "")
        return try {
            when {
                trimmed.startsWith("mandala://", ignoreCase = true) -> parseMandala(trimmed)
                trimmed.startsWith("vmess://", ignoreCase = true) -> parseVmess(trimmed)
                trimmed.startsWith("vless://", ignoreCase = true) -> parseVless(trimmed)
                trimmed.startsWith("trojan://", ignoreCase = true) -> parseTrojan(trimmed)
                // [修复] 支持 Shadowsocks 和 Socks5 (包含 socks://)
                trimmed.startsWith("ss://", ignoreCase = true) -> parseShadowsocks(trimmed)
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
            protocol = "vless", // 注意：VMess 在此项目中映射为 Vless 处理 (根据原有代码逻辑)
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

    // [修复] 解析 Shadowsocks 链接 (增加 Plugin 支持)
    // 支持 ss://method:password@host:port 和 ss://BASE64(method:password)@host:port
    private fun parseShadowsocks(link: String): Node? {
        var cleanLink = link
        var tag = "未命名SS"

        // 提取 Tag (#后面的内容)
        if (link.contains("#")) {
            tag = Uri.decode(link.substringAfterLast("#"))
            cleanLink = link.substringBeforeLast("#")
        }

        // 尝试解析 URI
        var uri = Uri.parse(cleanLink)
        var host = uri.host
        var port = uri.port
        var userInfo = uri.userInfo ?: ""

        // 如果 host 为空，可能是 ss://BASE64_ALL 格式
        if (host.isNullOrEmpty()) {
            // 移除 ss:// 前缀，且只取 ? 之前的部分进行 Base64 解码，避免参数干扰
            val base64Full = cleanLink.removePrefix("ss://")
            val base64Clean = if (base64Full.contains("?")) base64Full.substringBefore("?") else base64Full
            
            try {
                // 尝试 Base64 解码主体内容
                val decoded = String(Base64.decode(base64Clean, Base64.URL_SAFE or Base64.NO_WRAP), StandardCharsets.UTF_8)
                // 拼接回参数部分（如果有）
                val queryPart = if (base64Full.contains("?")) "?" + base64Full.substringAfter("?") else ""
                
                // 重新解析解码后的链接
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
                // 可能是 Base64 编码的 method:password
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

        // [新增] 解析 Plugin 参数 (解决 SS 连接迟钝/不通问题)
        // 格式示例: plugin=v2ray-plugin;mode=websocket;host=...
        val plugin = uri.getQueryParameter("plugin")
        val paramSni = uri.getQueryParameter("sni")
        
        var transport = "tcp"
        var finalSni = paramSni ?: ""
        var finalPath = "/"
        
        if (!plugin.isNullOrEmpty()) {
            val decodedPlugin = Uri.decode(plugin)
            val parts = decodedPlugin.split(";")
            
            var pluginMode = ""
            var pluginHost = ""
            var pluginPath = ""
            
            for (part in parts) {
                val p = part.trim()
                when {
                    p.startsWith("mode=") -> pluginMode = p.substringAfter("mode=")
                    p.startsWith("host=") -> pluginHost = p.substringAfter("host=")
                    p.startsWith("obfs-host=") -> pluginHost = p.substringAfter("obfs-host=")
                    p.startsWith("path=") -> pluginPath = p.substringAfter("path=")
                }
            }
            
            // 识别 WebSocket 模式
            if (pluginMode.equals("websocket", ignoreCase = true) || 
                pluginMode.equals("ws", ignoreCase = true) || 
                decodedPlugin.contains("v2ray-plugin")) {
                
                transport = "ws"
                if (pluginPath.isNotEmpty()) finalPath = pluginPath
                if (pluginHost.isNotEmpty()) finalSni = pluginHost
            }
        }

        return Node(
            tag = tag,
            protocol = "shadowsocks",
            server = host!!,
            port = if (port > 0) port else 8388,
            password = Uri.decode(password),
            uuid = Uri.decode(method), // 将加密方式 (Method) 存入 uuid 字段
            transport = transport,     // 正确设置传输方式
            path = finalPath,          // 正确设置路径
            sni = finalSni             // 正确设置 SNI
        )
    }

    // [修复] 解析 Socks 链接 (支持 socks:// 和 socks5://)
    // 格式: socks://BASE64_USER_INFO@host:port 或 socks5://user:pass@host:port
    private fun parseSocks5(link: String): Node? {
        val uri = Uri.parse(link)
        val host = uri.host ?: return null
        var userInfo = uri.userInfo ?: ""
        
        var username = ""
        var password = ""

        // [新增] 智能处理 UserInfo (优先尝试 Base64 解码)
        // 很多订阅链接的 socks:// 使用 Base64 编码的 user:pass
        if (userInfo.isNotEmpty()) {
            var decodedSuccess = false
            // 如果不含冒号，或者链接头是 socks:// (通常暗示 Base64)，尝试解码
            if (!userInfo.contains(":") || link.startsWith("socks://", ignoreCase = true)) {
                try {
                    val decoded = String(Base64.decode(userInfo, Base64.URL_SAFE or Base64.NO_WRAP), StandardCharsets.UTF_8)
                    if (decoded.contains(":")) {
                        username = decoded.substringBefore(":")
                        password = decoded.substringAfter(":")
                        decodedSuccess = true
                    }
                } catch (e: Exception) {
                    // 解码失败，回退到原始值
                }
            }

            if (!decodedSuccess) {
                if (userInfo.contains(":")) {
                    username = userInfo.substringBefore(":")
                    password = userInfo.substringAfter(":")
                } else {
                    username = userInfo
                }
            }
        }

        // [新增] 解析 URL 参数 (sni, path, type)
        // 解决部分高级 Socks5 节点无法连接的问题
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
            password = Uri.decode(password), // 密码
            uuid = Uri.decode(username),     // 将用户名存入 uuid 字段
            transport = transport,           // 支持 ws
            path = finalPath,                // 支持 path
            sni = finalSni                   // 支持 sni
        )
    }
}
