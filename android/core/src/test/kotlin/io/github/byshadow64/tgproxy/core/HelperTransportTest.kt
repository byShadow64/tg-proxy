package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.net.Socket
import java.security.MessageDigest
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLSocket

class HelperTransportTest {
    private val token = "local-fixture-token-".repeat(3)
    private fun settings(port: Int, pin: String = TlsFixture.pin) = HelperSettings("127.0.0.1", port, pin, token)

    @Test fun helperAuthenticatesBeforeRelayingEmptyAndBinaryFrames() {
        TlsFixture.server { socket ->
            assertEquals(token, readHelper(socket).toString(Charsets.UTF_8))
            assertEquals("kws2.web.telegram.org", readHelper(socket).toString(Charsets.US_ASCII))
            writeHelper(socket, "OK".toByteArray())
            repeat(2) { writeHelper(socket, readHelper(socket)) }
        }.use { server ->
            SessionIo().use { io ->
                HelperTransport.connect(settings(server.port), "kws2.web.telegram.org", io).use { transport ->
                    for (payload in listOf(ByteArray(0), ByteArray(100_003) { it.toByte() })) {
                        transport.send(payload)
                        val received = java.io.ByteArrayOutputStream()
                        do { val part = transport.receive()!!; assertTrue(part.size <= STREAM_CHUNK_BYTES); received.write(part) } while (received.size() < payload.size)
                        assertArrayEquals(payload, received.toByteArray())
                    }
                }
            }
            server.assertSuccess()
        }
    }

    @Test fun wrongPinSendsNoTokenOrRouteBytes() {
        val applicationBytes = AtomicInteger()
        TlsFixture.server { socket ->
            try {
                (socket as SSLSocket).startHandshake()
                val byte = socket.getInputStream().read()
                if (byte >= 0) applicationBytes.incrementAndGet()
            } catch (_: Exception) {}
        }.use { server ->
            SessionIo().use { io ->
                try { HelperTransport.connect(settings(server.port, "00".repeat(32)), "kws2.web.telegram.org", io); fail() }
                catch (_: PinMismatchException) {}
            }
            server.assertSuccess()
            assertEquals(0, applicationBytes.get())
        }
    }

    @Test fun rejectsAuthorizationAndOversizedFrameBeforeBodyAllocation() {
        for (oversized in listOf(false, true)) {
            TlsFixture.server { socket ->
                readHelper(socket); readHelper(socket)
                writeHelper(socket, if (oversized) "OK".toByteArray() else "DENIED".toByteArray())
                if (oversized) socket.getOutputStream().apply { write(byteArrayOf(1, 0, 0, 1)); flush() }
            }.use { server ->
                SessionIo().use { io ->
                    try {
                        HelperTransport.connect(settings(server.port), "kws2.web.telegram.org", io).use { if (oversized) it.receive() }
                        fail()
                    } catch (error: Exception) {
                        if (oversized) assertTrue(error is ProtocolException) else assertTrue(error is HelperRejectedException)
                    }
                }
                server.assertSuccess()
            }
        }
    }

    @Test fun engineStopsDuringTlsAndAuthorizationHandshakeWithoutFallback() {
        for (tlsEstablished in listOf(false, true)) {
            val ready = java.util.concurrent.CountDownLatch(1)
            val body: (Socket) -> Unit = { socket ->
                if (tlsEstablished) { readHelper(socket); readHelper(socket) }
                ready.countDown()
                // The first case deliberately never answers the TLS ClientHello.
                while (socket.getInputStream().read() >= 0) { }
            }
            val server = if (tlsEstablished) TlsFixture.server(body) else LocalServer(body = body)
            server.use {
                val port = freePort()
                val events = CopyOnWriteArrayList<EngineEvent>()
                ProxyEngine(EngineConfig(port, "04".repeat(16), settings(server.port)), events::add).use { engine ->
                    engine.start()
                    Socket("127.0.0.1", port).use { client ->
                        client.soTimeout = 3_000
                        client.getOutputStream().write(clientInit(hex("04".repeat(16)), TransportProtocol.INTERMEDIATE, 2))
                        assertTrue(ready.await(3, java.util.concurrent.TimeUnit.SECONDS))
                        val began = System.nanoTime()
                        engine.stop()
                        assertTrue(java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - began) < 2_500)
                        assertEquals(-1, client.getInputStream().read())
                        assertEquals(0, engine.snapshot().activeConnections)
                        assertEquals(0L, engine.snapshot().directConnections)
                        assertFalse(events.any { it.code == EventCode.ROUTE_CONNECTED })
                    }
                }
                server.assertSuccess()
            }
        }
    }

    @Test fun saturatedUplinkExecutorClosesAcceptedSessionBeforeDialing() {
        val events = CopyOnWriteArrayList<EngineEvent>()
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val dials = AtomicInteger()
        val port = freePort()
        val connector: (ClientHandshake, SessionIo) -> BinaryTransport = { _, _ -> dials.incrementAndGet(); throw AssertionError("Rejected ingress must not dial") }
        ProxyEngine(EngineConfig(port, "05".repeat(16), maxConnections = 1), connector, events::add).use { engine ->
            engine.start()
            val run = ProxyEngine::class.java.getDeclaredField("run").apply { isAccessible = true }.get(engine)
            val executor = run.javaClass.getDeclaredField("uplinks").apply { isAccessible = true }.get(run) as java.util.concurrent.ThreadPoolExecutor
            try {
                executor.execute { entered.countDown(); release.await() }
                assertTrue(entered.await(1, java.util.concurrent.TimeUnit.SECONDS))
                executor.execute { }
                Socket("127.0.0.1", port).use { client ->
                    client.soTimeout = 3_000
                    client.getOutputStream().write(clientInit(hex("05".repeat(16)), TransportProtocol.INTERMEDIATE, 2))
                    assertEquals(-1, client.getInputStream().read())
                }
                await { engine.snapshot().activeConnections == 0 && events.any { it.code == EventCode.CONNECTION_LIMIT } }
                assertEquals(1, events.count { it.code == EventCode.CONNECTION_CLOSED })
                assertEquals(0, dials.get())
                assertFalse(events.any { it.code == EventCode.UPSTREAM_UNAVAILABLE })
            } finally { release.countDown() }
        }
    }

    @Test fun fullEngineRelaysAllProtocolsAndCoalescesOneMiBMedia() {
        for (protocol in TransportProtocol.entries) {
            val secret = ByteArray(16) { it.toByte() }
            val body = ByteArray(1024 * 1024) { (it * 17).toByte() }
            val payload = if (protocol == TransportProtocol.ABRIDGED) byteArrayOf(0x7f, 0, 0, 4) + body else {
                val padded = body + if (protocol == TransportProtocol.PADDED_INTERMEDIATE) ByteArray(15) { 0x42 } else ByteArray(0)
                byteArrayOf(padded.size.toByte(), (padded.size ushr 8).toByte(), (padded.size ushr 16).toByte(), 0) + padded
            }
            val reply = ByteArray(70_003) { (it * 13).toByte() }
            val events = CopyOnWriteArrayList<EngineEvent>()
            TlsFixture.server { socket ->
                assertEquals(token, readHelper(socket).toString(Charsets.UTF_8))
                assertEquals("kws4-1.web.telegram.org", readHelper(socket).toString(Charsets.US_ASCII))
                writeHelper(socket, "OK".toByteArray())
                val relay = readHelper(socket)
                assertEquals(64, relay.size)
                val decrypt = StreamCipher(relay.copyOfRange(8, 40), relay.copyOfRange(40, 56)).also { it.skipInit() }
                val received = java.io.ByteArrayOutputStream()
                while (received.size() < payload.size) {
                    val frame = readHelper(socket)
                    assertEquals(payload.size, frame.size)
                    received.write(decrypt.update(frame))
                }
                assertArrayEquals(payload, received.toByteArray())
                val reverse = relay.copyOfRange(8, 56).reversedArray()
                writeHelper(socket, StreamCipher(reverse.copyOfRange(0, 32), reverse.copyOfRange(32, 48)).update(reply))
                // Keep the relay alive until the client observes its response and closes.
                socket.getInputStream().read()
            }.use { server ->
                val port = freePort()
                ProxyEngine(EngineConfig(port, secret.joinToString("") { "%02x".format(it.toInt() and 255) }, settings(server.port)), events::add).use { engine ->
                    engine.start()
                    Socket("127.0.0.1", port).use { client ->
                        client.soTimeout = 5_000
                        val init = clientInit(secret, protocol, -4)
                        client.getOutputStream().write(init)
                        val upload = StreamCipher(MessageDigest.getInstance("SHA-256").digest(init.copyOfRange(8, 40) + secret), init.copyOfRange(40, 56)).also { it.skipInit() }
                        client.getOutputStream().write(upload.update(payload))
                        val reverse = init.copyOfRange(8, 56).reversedArray()
                        val download = StreamCipher(MessageDigest.getInstance("SHA-256").digest(reverse.copyOfRange(0, 32) + secret), reverse.copyOfRange(32, 48))
                        assertArrayEquals(reply, download.update(client.getInputStream().exactly(reply.size)))
                        await { engine.snapshot().bytesUp == payload.size.toLong() && engine.snapshot().bytesDown == reply.size.toLong() }
                        assertEquals(1L, engine.snapshot().helperConnections)
                        assertTrue(events.any { it.code == EventCode.ROUTE_CONNECTED && it.route == RouteKind.HELPER_TLS && it.dc == 4 && it.media })
                    }
                }
                server.assertSuccess()
            }
        }
    }
}
