package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Local sockets only: rejected inputs must not even start route selection or lease lookup. */
class TelegramOnlyAdmissionTest {
    private val secretHex = "31".repeat(16)
    private val secret = hex(secretHex)

    private fun foreignInputs(): List<ByteArray> = listOf(
        byteArrayOf(19) + "BitTorrent protocol".toByteArray(Charsets.US_ASCII) + ByteArray(48),
        byteArrayOf(5, 1, 0), // SOCKS5 greeting, including short EOF.
        byteArrayOf(5, 1, 0, 1, 1, 2, 3, 4, 0, 80) + ByteArray(60),
        "CONNECT example.invalid:6881 HTTP/1.1\r\nHost: example.invalid\r\n\r\n".toByteArray(Charsets.US_ASCII),
        "GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n".toByteArray(Charsets.US_ASCII),
        byteArrayOf(0x16, 3, 1, 0, 80) + ByteArray(80),
        ByteArray(64),
        clientInit(hex("32".repeat(16)), TransportProtocol.INTERMEDIATE, 2),
    ) + listOf(0, 6, -6, 200, 201, 202, 204, 32767, -32768).map {
        clientInit(secret, TransportProtocol.PADDED_INTERMEDIATE, it)
    }

    private fun submit(port: Int, bytes: ByteArray, fragmented: Boolean) {
        Socket("127.0.0.1", port).use { client ->
            client.soTimeout = 2_000
            if (fragmented) {
                // The first prefix cannot be rejected just because a read was short.
                val split = minOf(7, bytes.size)
                client.getOutputStream().write(bytes, 0, split)
                client.getOutputStream().flush()
                Thread.sleep(5)
                client.getOutputStream().write(bytes, split, bytes.size - split)
            } else client.getOutputStream().write(bytes)
            client.shutdownOutput()
            val response = try { client.getInputStream().read() }
            catch (_: java.net.SocketException) { -1 } // A close with unread trailing bytes can reset TCP.
            assertEquals("Rejected ingress must close without responding", -1, response)
        }
    }

    @Test fun foreignProtocolsAndUnsupportedDcsNeverReachDirectConnector() {
        val dials = AtomicInteger()
        val connector: (ClientHandshake, SessionIo) -> BinaryTransport = { _, _ ->
            dials.incrementAndGet(); throw ProtocolException()
        }
        val port = freePort()
        ProxyEngine(EngineConfig(port, secretHex), connector).use { engine ->
            engine.start()
            for (fragmented in listOf(false, true)) for (bytes in foreignInputs()) submit(port, bytes, fragmented)
            assertEquals(0, dials.get())
            assertEquals(0L, engine.snapshot().bytesUp)
            assertEquals(0L, engine.snapshot().bytesDown)
        }
    }

    @Test fun foreignProtocolsAndUnsupportedDcsNeverFetchHelperLease() {
        val leases = AtomicInteger()
        val settings = HelperSettings("127.0.0.1", 1, "00".repeat(32), "fixture-token".repeat(4))
        val provider = HelperConnectionProvider { leases.incrementAndGet(); throw ProtocolException() }
        val port = freePort()
        ProxyEngine(EngineConfig(port, secretHex, settings), provider).use { engine ->
            engine.start()
            for (fragmented in listOf(false, true)) for (bytes in foreignInputs()) submit(port, bytes, fragmented)
            assertEquals(0, leases.get())
            assertEquals(0L, engine.snapshot().bytesUp)
            assertEquals(0L, engine.snapshot().bytesDown)
        }
    }

    @Test fun everySupportedProtocolDcAndMediaFlagStillReachesOneSelectedTransport() {
        for (protocol in TransportProtocol.entries) for (dc in listOf(1, 2, 3, 4, 5, 203)) for (media in listOf(false, true)) {
            val dials = AtomicInteger(); val writes = AtomicInteger(); val connected = CountDownLatch(1)
            val connector: (ClientHandshake, SessionIo) -> BinaryTransport = { handshake, io ->
                assertEquals(protocol, handshake.protocol); assertEquals(dc, handshake.dc); assertEquals(media, handshake.media)
                dials.incrementAndGet()
                object : BinaryTransport {
                    override fun send(bytes: ByteArray) { assertEquals(64, bytes.size); writes.incrementAndGet(); connected.countDown() }
                    override fun receive(): ByteArray? { while (!io.closed) Thread.sleep(5); return null }
                    override fun close() {}
                }
            }
            val port = freePort()
            ProxyEngine(EngineConfig(port, secretHex), connector).use { engine ->
                engine.start()
                Socket("127.0.0.1", port).use { client ->
                    val bytes = clientInit(secret, protocol, if (media) -dc else dc)
                    client.getOutputStream().write(bytes, 0, 7); client.getOutputStream().flush()
                    Thread.sleep(2); client.getOutputStream().write(bytes, 7, bytes.size - 7)
                    assertTrue(connected.await(2, TimeUnit.SECONDS))
                    assertEquals(1, dials.get()); assertEquals(1, writes.get())
                }
            }
        }
    }

    @Test fun policyPreservesEveryOfficialHelperRouteAndRelayDcAlias() {
        for (dc in listOf(1, 2, 3, 4, 5, 203)) for (media in listOf(false, true)) {
            val expected = "kws${if (dc == 203) 2 else dc}${if (media) "-1" else ""}.web.telegram.org"
            assertEquals(expected, TelegramRelayPolicy.officialDomain(dc, media))
            TelegramRelayPolicy.requireHelperDomain(expected)
            DirectRoutePlanner().use { planner ->
                val planned = planner.plan(ClientHandshake(dc, media, TransportProtocol.INTERMEDIATE, ByteArray(48)))
                assertTrue(planned.isNotEmpty())
                assertTrue(planned.filter { it.strategy != DirectStrategy.RELAY_WSS }.all { it.domain == expected })
                assertTrue(planned.filter { it.strategy == DirectStrategy.RELAY_WSS }.all {
                    it.host == it.domain && WssRelayCatalog.domains.any { suffix -> it.domain == "kws$dc.$suffix" }
                })
            }
        }
    }

    @Test fun plannerRejectsUnsupportedDcEvenWithoutEngineIngress() {
        DirectRoutePlanner().use { planner ->
            for (dc in listOf(0, -1, 6, 200, 201, 202, 204, Int.MIN_VALUE, Int.MAX_VALUE)) {
                try {
                    planner.plan(ClientHandshake(dc, false, TransportProtocol.INTERMEDIATE, ByteArray(48)))
                    fail("Planner accepted unsupported DC $dc")
                } catch (_: ProtocolException) { }
            }
        }
    }

    @Test fun helperRejectsNonCatalogRouteBeforeTlsOrCredentials() {
        // Deliberately invalid pin: a route error must occur before even pin parsing / TLS setup.
        val settings = HelperSettings("127.0.0.1", 1, "bad-pin", "fixture-token".repeat(4))
        for (domain in listOf("example.invalid", "kws6.web.telegram.org", "kws203.web.telegram.org",
            "kws2.web.telegram.org.evil.invalid", "kws2.web.telegram.org:443", "kws2.web.telegram.org.",
            "KWS2.web.telegram.org", "kws2.web.telegram.org\r\nX: value", "127.0.0.1", "kws2.cakeisalie.co.uk")) {
            SessionIo().use { io ->
                try { HelperTransport.connect(settings, domain, io); fail("Helper accepted foreign route") }
                catch (_: ProtocolException) { }
            }
        }
    }
}
