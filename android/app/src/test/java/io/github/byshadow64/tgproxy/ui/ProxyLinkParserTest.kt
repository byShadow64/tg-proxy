package io.github.byshadow64.tgproxy.ui

import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

class ProxyLinkParserTest {
    private val secret = "0123456789abcdef0123456789abcdef"
    private fun tg(server: String = "proxy.example.invalid", secret: String = this.secret) =
        "tg://proxy?server=$server&port=443&secret=$secret"
    private fun reject(link: String) {
        try { ProxyLinkParser.parse(link); fail("Untrusted input accepted") }
        catch (error: ProxyLinkException) {
            assertEquals("invalid_proxy_link", error.message)
            assertFalse(error.toString().contains(secret))
        }
    }

    @Test fun helperLinkIsIpOnlyAndRoundTrips() {
        val helper = ProxyLinkParser.parse("tgproxy://helper?ip=9.9.9.9") as HelperIpLink
        assertEquals("9.9.9.9", helper.ip)
        assertEquals("tgproxy://helper?ip=9.9.9.9", helper.uri)
        assertFalse(helper.toString().contains(helper.ip))
        val ipv6 = ProxyLinkParser.helperLink("2606:4700:4700:0:0:0:0:1111")
        assertEquals("2606:4700:4700::1111", (ProxyLinkParser.parse(ipv6.uri) as HelperIpLink).ip)
        assertFalse(ipv6.uri.contains("token"))
        assertFalse(ipv6.uri.contains("secret"))
    }

    @Test fun helperRejectsPrivateReservedNonNumericAndExtraCredentials() {
        for (ip in listOf("127.0.0.1", "10.0.0.1", "0.0.0.0", "169.254.169.254", "100.64.0.1",
            "192.168.1.1", "172.16.1.1", "192.0.2.1", "198.51.100.1", "203.0.113.1",
            "224.0.0.1", "255.255.255.255", "::1", "fe80::1", "fc00::1", "2001:db8::1",
            "::ffff:7f00:1", "example.invalid", "9.9.9.9:8444", "009.9.9.9", "9.9.9.9/32")) {
            reject("tgproxy://helper?ip=$ip")
        }
        for (suffix in listOf("&token=$secret", "&pin=$secret", "&port=8444", "&secret=$secret", "&ip=8.8.8.8",
            "&%69p=8.8.8.8", "&", "#fragment")) reject("tgproxy://helper?ip=9.9.9.9$suffix")
    }

    @Test fun telegramHexLinksCanonicalizeToExplicitTelegramHandoff() {
        val link = ProxyLinkParser.parse("https://t.me/proxy?secret=DD${secret.uppercase()}&server=PROXY.EXAMPLE.INVALID&port=443") as TelegramProxyLink
        assertEquals("proxy.example.invalid", link.host)
        assertEquals(443, link.port)
        assertFalse(link.isLoopback)
        assertEquals(tg(secret = "dd$secret"), link.uri)
        assertFalse(link.toString().contains(secret))
        assertFalse(link.toString().contains(link.host))
    }

    @Test fun telegramBase64AndFakeTlsSecretsAreBoundedAndValidated() {
        val bytes = ByteArray(16) { it.toByte() }
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        val parsed = ProxyLinkParser.parse(tg(secret = encoded)) as TelegramProxyLink
        assertTrue(parsed.uri.endsWith("secret=000102030405060708090a0b0c0d0e0f"))
        assertTrue((ProxyLinkParser.parse(tg(secret = "a".repeat(21) + "A")) as TelegramProxyLink).uri.contains("secret="))
        reject(tg(secret = "a".repeat(22))) // Nonzero unused padding bits are not canonical.
        val domain = "example.invalid".toByteArray().joinToString("") { "%02x".format(it) }
        assertTrue((ProxyLinkParser.parse(tg(secret = "ee$secret$domain")) as TelegramProxyLink).uri.endsWith("ee$secret$domain"))
        for (invalid in listOf("short", "x".repeat(541), "zz$secret", "ee$secret", "ee${secret}2f", "ff$secret", "$encoded=")) reject(tg(secret = invalid))
    }

    @Test fun loopbackLinksAreRecognizedWithoutTrustingTheirPortOrSecret() {
        for (host in listOf("127.0.0.1", "127.99.0.1", "localhost", "::1", "0:0:0:0:0:0:0:1", "::ffff:7f00:1", "::7f00:1")) {
            assertTrue(host, (ProxyLinkParser.parse(tg(host)) as TelegramProxyLink).isLoopback)
        }
        assertFalse((ProxyLinkParser.parse(tg("127.example.invalid")) as TelegramProxyLink).isLoopback)
        reject(tg("2130706433"))
        reject(tg("127.1"))
        reject(tg("0x7f000001"))
    }

    @Test fun duplicateUnknownParametersAuthorityTricksAndControlsAreRejected() {
        for (link in listOf(
            tg() + "&secret=$secret", tg() + "&%73ecret=$secret", tg() + "&token=$secret",
            tg() + "&unknown=1", tg() + "#fragment", tg().replace("port=443", "port=0"),
            tg().replace("port=443", "port=65536"), tg().replace("port=443", "port=-1"),
            tg().replace("server=proxy.example.invalid", "server=bad%0Ahost"),
            tg().replace("server=proxy.example.invalid", "server=bad%252ehost"),
            tg().replace("server=proxy.example.invalid", "server=one+two.example"),
            tg().replace("tg://proxy", "tg://user@proxy"), tg().replace("tg://proxy", "tg://proxy:443"),
            tg().replace("tg://proxy", "intent://proxy"), tg().replace("tg://proxy", "file://proxy"),
            tg().replace("tg://proxy", "https://t.me.evil.invalid/proxy"),
            tg().replace("tg://proxy", "https://user@t.me/proxy"),
            tg().replace("tg://proxy", "https://t.me:443/proxy"),
            tg().replace("tg://proxy", "http://t.me/proxy"), "\n" + tg(), tg() + "\u0000",
            "TGP2$secret", "tgproxy://helper?ip=9.9.9.9&port=8444", "x".repeat(2049),
        )) reject(link)
    }
}
