package com.example.mandala.utils

import android.net.Uri
import android.util.Base64
import com.example.mandala.viewmodel.Node
import com.google.gson.Gson
import com.google.gson.JsonObject
import java.nio.charset.StandardCharsets

object NodeParser {

    /**
     * 解析节点链接
     * 支持:
     * 1. vmess:// (Base64 JSON)
     * 2. trojan://password@host:port?queryParams#tag
     * 3. mandala:// (自定义 URI 格式)
     */
    fun parse(link: String): Node? {
        val trimmedLink = link.trim()
        return try {
            when {
                trimmedLink.startsWith("vmess://") -> parseVmess(trimmedLink)
                trimmedLink.startsWith("trojan://") -> parseTrojan(trimmedLink)
                trimmedLink.startsWith("mandala://") -> parseMandala(trimmedLink)
                else -> null
            }
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    // --- VMESS 解析 ---
    private fun parseVmess(link: String): Node? {
        val base64Str = link.removePrefix("vmess://")
        // 兼容 URL Safe 和标准 Base64
        val decodedBytes = try {
            Base64.decode(base64Str, Base64.DEFAULT)
        } catch (e: IllegalArgumentException) {
            Base64.decode(base64Str, Base64.URL_SAFE)
        }

        val jsonStr = String(decodedBytes, StandardCharsets.UTF_8)
        val json = Gson().fromJson(jsonStr, JsonObject::class.java)

        // 解析 V2RayN 格式字段
        val ps = json.get("ps")?.asString ?: "Unknown Vmess"
        val add = json.get("add")?.asString ?: return null
        val port = json.get("port")?.asString?.toIntOrNull() ?: 443
        val id = json.get("id")?.asString ?: ""
        val net = json.get("net")?.asString ?: "tcp"
        // val type = json.get("type")?.asString ?: "none"
        // val tls = json.get("tls")?.asString ?: ""

        // 统一 transport 类型命名
        val transport = if (net == "ws" || net == "websocket") "ws" else "tcp"

        // 注意：Mandala Core 目前逻辑是用 vless 协议处理 vmess 结构
        return Node(
            tag = ps,
            protocol = "vless",
            server = add,
            port = port,
            uuid = id,
            transport = transport
        )
    }

    // --- TROJAN 解析 ---
    // 格式: trojan://password@host:port?peer=sni&type=ws#tag
    private fun parseTrojan(link: String): Node? {
        val uri = Uri.parse(link)
        val userInfo = uri.userInfo ?: return null // password
        val host = uri.host ?: return null
        val port = uri.port.takeIf { it > 0 } ?: 443
        val tag = uri.fragment ?: "Trojan Node"

        val type = uri.getQueryParameter("type") ?: "tcp"
        // val sni = uri.getQueryParameter("peer") ?: uri.getQueryParameter("sni") ?: ""

        return Node(
            tag = tag,
            protocol = "trojan",
            server = host,
            port = port,
            password = userInfo,
            transport = if (type == "ws") "ws" else "tcp"
        )
    }

    // --- MANDALA 解析 ---
    // 格式: mandala://password@host:port?uuid=...&transport=ws#tag
    private fun parseMandala(link: String): Node? {
        val uri = Uri.parse(link)
        val userInfo = uri.userInfo ?: "" // password
        val host = uri.host ?: return null
        val port = uri.port.takeIf { it > 0 } ?: 443
        val tag = uri.fragment ?: "Mandala Node"

        val uuid = uri.getQueryParameter("uuid") ?: ""
        val transport = uri.getQueryParameter("transport") ?: "tcp"

        return Node(
            tag = tag,
            protocol = "mandala",
            server = host,
            port = port,
            password = userInfo,
            uuid = uuid,
            transport = transport
        )
    }
}
