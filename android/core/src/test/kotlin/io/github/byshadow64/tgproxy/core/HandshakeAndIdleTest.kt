package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class HandshakeAndIdleTest {
    private val secret = "31".repeat(16)

    @Test fun parserSeparatesWrongSecretAndMissingDcWithoutAcceptingEither() {
        for (protocol in TransportProtocol.entries) {
            val good = clientInit(hex(secret), protocol, 2)
            assertNull(Obfuscated2.inspect(good, hex(secret)).failure)
            assertEquals(HandshakeFailure.SECRET_OR_PROTOCOL, Obfuscated2.inspect(good, hex("32".repeat(16))).failure)
            assertEquals(HandshakeFailure.ZERO_DC, Obfuscated2.inspect(clientInit(hex(secret), protocol, 0), hex(secret)).failure)
            assertEquals(HandshakeFailure.RESERVED_DC, Obfuscated2.inspect(clientInit(hex(secret), protocol, Short.MIN_VALUE.toInt()), hex(secret)).failure)
            assertEquals(HandshakeFailure.INVALID_LENGTH, Obfuscated2.inspect(good.copyOf(63), hex(secret)).failure)
            assertEquals(HandshakeFailure.INVALID_LENGTH, Obfuscated2.inspect(good, ByteArray(17)).failure)
        }
    }

    @Test fun staleSecretRetriesNeverDialOrSendAnythingUpstream() {
        val dials = AtomicInteger(); val events = CopyOnWriteArrayList<EngineEvent>(); val port = freePort()
        val connector: (ClientHandshake, SessionIo) -> BinaryTransport = { _, _ -> dials.incrementAndGet(); error("Unverified client must never reach upstream") }
        ProxyEngine(EngineConfig(port, secret), connector, events::add).use { engine ->
            engine.start()
            repeat(12) { index ->
                Socket("127.0.0.1", port).use { client ->
                    client.soTimeout = 1_000
                    val dc = if (index % 2 == 0) 2 else -4
                    client.getOutputStream().write(clientInit(hex("32".repeat(16)), TransportProtocol.entries[index % 3], dc))
                    assertEquals(-1, client.getInputStream().read())
                }
            }
            await { engine.snapshot().activeConnections == 0 }
            assertEquals(0, dials.get()); assertEquals(0L, engine.snapshot().bytesUp); assertEquals(0L, engine.snapshot().bytesDown)
            val rejected = events.filter { it.code == EventCode.INVALID_HANDSHAKE }
            assertEquals(12, rejected.size)
            assertTrue(rejected.all { it.handshakeFailure == HandshakeFailure.SECRET_OR_PROTOCOL && it.stage == EngineStage.CLIENT_HANDSHAKE && it.dc == null && it.routeStrategy == null })
        }
    }

    @Test fun noClientsMeansNoDialOrAutonomousMtProtoTraffic() {
        val dials = AtomicInteger(); val port = freePort()
        val connector: (ClientHandshake, SessionIo) -> BinaryTransport = { _, _ -> dials.incrementAndGet(); error("No client") }
        ProxyEngine(EngineConfig(port, secret), connector).use { engine ->
            engine.start(); Thread.sleep(350)
            assertEquals(0, dials.get()); assertEquals(0L, engine.snapshot().totalConnections)
            assertEquals(0L, engine.snapshot().bytesUp); assertEquals(0L, engine.snapshot().bytesDown)
        }
    }

    @Test fun quietVerifiedClientSendsExactlyOneInitAndNoRepeatedForwarding() {
        val dials = AtomicInteger(); val sent = CopyOnWriteArrayList<ByteArray>(); val connected = CountDownLatch(1); val port = freePort()
        val connector: (ClientHandshake, SessionIo) -> BinaryTransport = { _, io ->
            dials.incrementAndGet()
            object : BinaryTransport {
                override fun send(bytes: ByteArray) { sent += bytes.copyOf(); connected.countDown() }
                override fun receive(): ByteArray? { while (!io.closed) Thread.sleep(5); return null }
                override fun close() {}
            }
        }
        ProxyEngine(EngineConfig(port, secret), connector).use { engine ->
            engine.start()
            Socket("127.0.0.1", port).use { client ->
                client.getOutputStream().write(clientInit(hex(secret), TransportProtocol.PADDED_INTERMEDIATE, 2))
                assertTrue(connected.await(1, TimeUnit.SECONDS)); Thread.sleep(350)
                assertEquals(1, dials.get()); assertEquals(listOf(64), sent.map { it.size })
                assertEquals(0L, engine.snapshot().bytesUp); assertEquals(0L, engine.snapshot().bytesDown)
            }
            await { engine.snapshot().activeConnections == 0 }
        }
    }

    @Test fun websocketIdleKeepaliveHasSixByteWireBoundPerThirtySeconds() {
        val received = AtomicInteger()
        LocalServer { socket ->
            serveUpgrade(socket)
            repeat(60) {
                val ping = readClientWs(socket)
                assertEquals(9, ping.first); assertEquals(0, ping.second.size)
                // Empty masked RFC6455 control frame: two header bytes and four mask bytes.
                received.addAndGet(6)
            }
            assertEquals(-1, socket.getInputStream().read())
        }.use { server ->
            SessionIo().use { io ->
                WebSocketTransport.upgrade(io.track(Socket("127.0.0.1", server.port)), "localhost", io).use { transport ->
                    val start = System.nanoTime()
                    assertFalse(transport.claimKeepAlive(start + TimeUnit.SECONDS.toNanos(29)))
                    repeat(60) { index ->
                        val tick = start + TimeUnit.SECONDS.toNanos((index + 1L) * 30)
                        assertTrue(transport.claimKeepAlive(tick)); assertFalse(transport.claimKeepAlive(tick))
                        transport.keepAlive()
                    }
                }
            }
            server.assertSuccess(); assertEquals(360, received.get())
        }
    }

    companion object {
        private fun await(predicate: () -> Boolean) {
            val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
            while (!predicate() && System.nanoTime() < end) Thread.sleep(5)
            assertTrue(predicate())
        }
    }
}
