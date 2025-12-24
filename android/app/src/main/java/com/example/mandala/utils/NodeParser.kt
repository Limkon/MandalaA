// 文件路径: android/app/src/main/java/com/example/mandala/utils/NodeParser.kt

package com.example.mandala.utils

import android.net.Uri
import android.util.Base64
import com.example.mandala.viewmodel.Node
import com.google.gson.Gson
import com.google.gson.JsonObject
import java.nio.charset.StandardCharsets

object NodeParser {
    
    // [增强] 批量解析方法：增加对 Base64 编码订阅内容的自动识别与解码
    fun parseList(text: String): List<Node> {
        var content = text.trim()
        val nodes = mutableListOf<Node>()

        // 自动识别并尝试解码 Base64 (大多数 V2Ray/SS 订阅格式)
        if (!content.contains("://")) {
            try {
                val decoded = String(
                    Base64.decode(content, Base64.DEFAULT),
                    StandardCharsets.UTF_8
                )
                content = decoded
            } catch (e: Exception) {
                // 如果解码失败，保持原样按行解析
            }
        }

        // 使用正则按空白字符（换行、空格、制表符）分割
        val lines = content.split("\\s+".toRegex())
        
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
            protocol = "vless", 
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

    private fun parseShadowsocks(link: String): Node? {
        var cleanLink = link
        var tag = "未命名SS"

        if (link.contains("#")) {
            tag = Uri.decode(link.substringAfterLast("#"))
            cleanLink = link.substringBeforeLast("#")
        }

        var uri = Uri.parse(cleanLink)
        var host = uri.host
        var port = uri.port
        var userInfo = uri.userInfo ?: ""

        if (host.isNullOrEmpty()) {
            val base64Full = cleanLink.removePrefix("ss://")
            val base64Clean = if (base64Full.contains("?")) base64Full.substringBefore("?") else base64Full
            
            try {
                val decoded = String(Base64.decode(base64Clean, Base64.URL_SAFE or Base64.NO_WRAP), StandardCharsets.UTF_8)
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
            uuid = Uri.decode(method),
            transport = transport,
            path = finalPath,
            sni = finalSni
        )
    }

    private fun parseSocks5(link: String): Node? {
        val uri = Uri.parse(link)
        val host = uri.host ?: return null
        var userInfo = uri.userInfo ?: ""
        
        var username = ""
        var password = ""

        if (userInfo.isNotEmpty()) {
            var decodedSuccess = false
            if (!userInfo.contains(":") || link.startsWith("socks://", ignoreCase = true)) {
                try {
                    val decoded = String(Base64.decode(userInfo, Base64.URL_SAFE or Base64.NO_WRAP), StandardCharsets.UTF_8)
                    if (decoded.contains(":")) {
                        username = decoded.substringBefore(":")
                        password = decoded.substringAfter(":")
                        decodedSuccess = true
                    }
                } catch (e: Exception) { }
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
            transport = transport,
            path = finalPath,
            sni = finalSni
        )
    }
}
