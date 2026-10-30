package io.github.byshadow64.tgproxy.ui

import io.github.byshadow64.tgproxy.core.HelperRegistryClient
import java.net.IDN
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.Base64
import java.util.Locale

/** Parsed inputs are memory-only. Never log, persist, or put them into saved state. */
sealed interface ParsedProxyLink

class HelperIpLink internal constructor(val ip: String) : ParsedProxyLink {
    val uri: String get() = "tgproxy://helper?ip=" + URLEncoder.encode(ip, "UTF-8")
    override fun toString() = "HelperIpLink(<private>)"
}

class TelegramProxyLink internal constructor(
    val host: String,
    val port: Int,
    private val secretHex: String,
) : ParsedProxyLink {
    val isLoopback: Boolean = host == "localhost" || host == "::1" ||
        host.matches(Regex("127\\.[0-9]+\\.[0-9]+\\.[0-9]+")) ||
        host.matches(Regex("(?:::ffff:|::)7f[0-9a-f]{2}:[0-9a-f]{1,4}"))
    /** Only hand this to a known Telegram package after explicit confirmation. */
    val uri: String get() = "tg://proxy?server=${encode(host)}&port=$port&secret=$secretHex"
    override fun toString() = "TelegramProxyLink(<private>)"
    private fun encode(value: String) = URLEncoder.encode(value, "UTF-8").replace("+", "%20")
}

class ProxyLinkException : IllegalArgumentException("invalid_proxy_link")

/** Pure bounded syntax validation: no clipboard, DNS, HTTP, configuration or service effects. */
object ProxyLinkParser {
    const val MAX_LINK_LENGTH = 2048

    fun helperLink(ip: String): HelperIpLink = try { HelperIpLink(publicIp(ip)) }
        catch (_: Exception) { throw ProxyLinkException() }

    fun parse(input: String): ParsedProxyLink = try {
        require(input.length <= MAX_LINK_LENGTH)
        require(input.none { it.code < 32 || it.code == 127 })
        val text = input.trim()
        require(text.isNotEmpty() && text.none { it.isWhitespace() || it.code < 32 || it.code == 127 })
        val link = URI(text)
        require(!link.isOpaque && link.rawUserInfo == null && link.port == -1 && link.rawFragment == null)
        val scheme = link.scheme?.lowercase(Locale.ROOT)
        val authority = link.rawAuthority?.lowercase(Locale.ROOT)
        val helper = scheme == "tgproxy" && authority == "helper" && link.rawPath.orEmpty().isEmpty()
        val telegram = (scheme == "tg" && authority == "proxy" && link.rawPath.orEmpty().isEmpty()) ||
            (scheme == "https" && authority == "t.me" && link.rawPath == "/proxy")
        require(helper || telegram)
        val query = query(link.rawQuery ?: throw ProxyLinkException())
        if (helper) {
            require(query.keys == setOf("ip"))
            HelperIpLink(publicIp(query.getValue("ip")))
        } else {
            require(query.keys == setOf("server", "port", "secret"))
            val portText = query.getValue("port")
            require(portText.matches(Regex("[0-9]{1,5}")))
            val port = portText.toInt()
            require(port in 1..65535)
            TelegramProxyLink(host(query.getValue("server")), port, secret(query.getValue("secret")))
        }
    } catch (_: Exception) { throw ProxyLinkException() }

    private fun query(raw: String): Map<String, String> {
        require(raw.length <= MAX_LINK_LENGTH)
        val result = linkedMapOf<String, String>()
        for (pair in raw.split('&')) {
            val pieces = pair.split('=', limit = 2)
            require(pieces.size == 2)
            val key = decode(pieces[0])
            val value = decode(pieces[1])
            require(key.isNotEmpty() && value.isNotEmpty() && !result.containsKey(key))
            result[key] = value
        }
        return result
    }

    private fun decode(value: String): String {
        // URI components here are ASCII. No ambiguous '+', double escapes,
        // controls or replacement characters may survive percent decoding.
        require(value.all { it.code in 33..126 } && '+' !in value)
        val decoded = URLDecoder.decode(value, "UTF-8")
        require(decoded.none { it.isWhitespace() || it.code < 32 || it.code == 127 || it == '%' || it == '\uFFFD' })
        return decoded
    }

    private fun host(value: String): String {
        require(value.length in 1..253 && value.none { it in "/\\@?#%[]" })
        if (':' in value || value.all { it in "0123456789." }) return HelperRegistryClient.numericIp(value)
        val ascii = IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT)
        require((ascii == "localhost" || ('.' in ascii && ascii.substringAfterLast('.').any { it in 'a'..'z' })) &&
            ascii.length <= 253 && ascii.split('.').all {
            it.isNotEmpty() && it.length <= 63 && !it.startsWith('-') && !it.endsWith('-')
        })
        return ascii
    }

    private fun publicIp(value: String): String {
        val ip = HelperRegistryClient.numericIp(value)
        if (':' in ip) {
            val first = ip.substringBefore(':').toIntOrNull(16) ?: 0
            require(first in 0x2000..0x3fff && !ip.startsWith("2001:db8:") &&
                !(ip.startsWith("2001:") && (ip.substringAfter(':').substringBefore(':').toIntOrNull(16) ?: 0) < 0x200))
        } else {
            val p = ip.split('.').map(String::toInt)
            require(p[0] !in setOf(0, 10, 127) && p[0] < 224 &&
                !(p[0] == 100 && p[1] in 64..127) && !(p[0] == 169 && p[1] == 254) &&
                !(p[0] == 172 && p[1] in 16..31) && !(p[0] == 192 && (p[1] == 168 ||
                    (p[1] == 0 && p[2] in setOf(0, 2)) || (p[1] == 88 && p[2] == 99))) &&
                !(p[0] == 198 && (p[1] in 18..19 || (p[1] == 51 && p[2] == 100))) &&
                !(p[0] == 203 && p[1] == 0 && p[2] == 113))
        }
        return ip
    }

    private fun secret(value: String): String {
        require(value.length in 22..540)
        val bytes = if (value.length >= 32 && value.length % 2 == 0 && value.all { it in "0123456789abcdefABCDEF" }) {
            value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        } else {
            require(value.all { it in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" })
            Base64.getUrlDecoder().decode(value).also {
                require(Base64.getUrlEncoder().withoutPadding().encodeToString(it) == value)
            }
        }
        when {
            bytes.size == 16 -> Unit
            bytes.size == 17 -> require(bytes[0] == 0xdd.toByte())
            bytes.size in 18..270 -> {
                require(bytes[0] == 0xee.toByte())
                val domain = bytes.drop(17).map { (it.toInt() and 255).toChar() }.joinToString("")
                require(domain.all { it.code in 33..126 } && host(domain) == domain.lowercase(Locale.ROOT) && ':' !in domain)
            }
            else -> throw ProxyLinkException()
        }
        return bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
    }
}
