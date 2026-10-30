package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicInteger

class RelayEndToEndTest {
    @Test fun failedDnsStillUsesStrictNumericMediaRouteWithoutReplayForBothDcsAndAllProtocols() {
        for (dc in listOf(2, 4)) for (protocol in TransportProtocol.entries) {
            val requests = AtomicInteger()
            TlsFixture.server { socket -> serveAnonymousTelegram(socket, protocol, -dc, requests) }.use { server ->
                DirectRoutePlanner({ route, io ->
                    if (route.strategy != DirectStrategy.FIXED_IP) io.operation("dns", 100) { throw java.net.UnknownHostException() }
                    else WebSocketTransport.connect("127.0.0.1", "localhost", io, server.port, TlsFixture.clientFactory)
                }, hedgeMillis = 0).use { planner ->
                    val port = freePort(); val events = java.util.concurrent.CopyOnWriteArrayList<EngineEvent>()
                    val connector: (ClientHandshake, SessionIo) -> BinaryTransport = { h, io -> planner.connect(h, io) }
                    ProxyEngine(EngineConfig(port, "27".repeat(16)), connector, events::add).use { engine ->
                        engine.start(); reqPq(port, "27".repeat(16), protocol, dc)
                        assertEquals(1, requests.get())
                        val selected = events.single { it.code == EventCode.ROUTE_CONNECTED }
                        assertEquals(RouteStrategy.FIXED_IP, selected.routeStrategy)
                        assertEquals(dc, selected.dc); assertTrue(selected.media); assertNull(selected.relayCatalogIndex)
                    }
                }
                server.assertSuccess()
            }
        }
    }

    @Test fun blockedDirectFallsBackToAuthenticatedTlsAndFakeTelegramForAllProtocols() {
        for (protocol in TransportProtocol.entries) {
            val requestCount = AtomicInteger()
            TlsFixture.server { socket ->
                serveUpgrade(socket)
                val init = readClientWs(socket).second
                assertEquals(64, init.size)
                val decrypt = StreamCipher(init.copyOfRange(8, 40), init.copyOfRange(40, 56))
                val decodedInit = decrypt.update(init)
                assertTrue((56..59).all { decodedInit[it].toInt() and 255 == protocol.tag })
                assertEquals(-2, ByteBuffer.wrap(decodedInit, 60, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt())
                val packet = decrypt.update(readClientWs(socket).second)
                val header = if (protocol == TransportProtocol.ABRIDGED) 1 else 4
                val request = packet.copyOfRange(header, packet.size)
                assertArrayEquals(ByteArray(8), request.copyOfRange(0, 8))
                assertEquals(0xbe7e8ef1.toInt(), ByteBuffer.wrap(request, 20, 4).order(ByteOrder.LITTLE_ENDIAN).int)
                val nonce = request.copyOfRange(24, 40)
                requestCount.incrementAndGet()
                val body = le(0x05162463) + nonce + ByteArray(16) { 7 } + byteArrayOf(1, 1, 0, 0) + le(0x1cb5c415) + le(0)
                val message = ByteArray(8) + ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(1).array() + le(body.size) + body
                val frame = if (protocol == TransportProtocol.ABRIDGED) byteArrayOf((message.size / 4).toByte()) + message else le(message.size) + message
                val reverse = init.copyOfRange(8, 56).reversedArray()
                socket.getOutputStream().apply { write(wsFrame(2, StreamCipher(reverse.copyOfRange(0, 32), reverse.copyOfRange(32, 48)).update(frame))); flush() }
                socket.getInputStream().read()
            }.use { server ->
                DirectRoutePlanner({ route, io ->
                    if (route.strategy != DirectStrategy.RELAY_WSS) { while (!io.closed) Thread.sleep(5); throw java.io.EOFException() }
                    WebSocketTransport.connect("127.0.0.1", "localhost", io, server.port, TlsFixture.clientFactory)
                }, setupTimeoutMillis = 1500, hedgeMillis = 0).use { planner ->
                    val port = freePort(); val events = java.util.concurrent.CopyOnWriteArrayList<EngineEvent>()
                    val connector: (ClientHandshake, SessionIo) -> BinaryTransport = { h, io -> planner.connect(h, io) }
                    ProxyEngine(EngineConfig(port, "26".repeat(16)), connector, events::add).use { engine ->
                        engine.start()
                        reqPq(port, "26".repeat(16), protocol)
                        assertEquals(1, requestCount.get())
                        assertEquals(1L, engine.snapshot().relayConnections)
                        assertTrue(events.any { it.code == EventCode.ROUTE_CONNECTED && it.route == RouteKind.RELAY_WSS })
                        val selected = events.single { it.code == EventCode.ROUTE_CONNECTED }
                        assertEquals(RouteStrategy.RELAY_WSS, selected.routeStrategy)
                        assertTrue(selected.relayCatalogIndex in 0..3)
                    }
                }
                server.assertSuccess()
            }
        }
    }

    @Test fun relayStillRequiresHostnameBeforeAnyMtProtoPayload() {
        val applicationBytes = AtomicInteger()
        TlsFixture.server { socket ->
            try { if (socket.getInputStream().read() >= 0) applicationBytes.incrementAndGet() } catch (_: Exception) {}
        }.use { server ->
            DirectRoutePlanner({ route, io ->
                if (route.strategy != DirectStrategy.RELAY_WSS) throw java.net.ConnectException()
                WebSocketTransport.connect("127.0.0.1", "kws2.cakeisalie.co.uk", io, server.port, TlsFixture.clientFactory)
            }, setupTimeoutMillis = 500, hedgeMillis = 0).use { planner ->
                SessionIo().use { io ->
                    try { planner.connect(ClientHandshake(2, true, TransportProtocol.INTERMEDIATE, ByteArray(48)), io); fail() } catch (_: Exception) {}
                }
            }
            server.assertSuccess()
            assertEquals(0, applicationBytes.get())
        }
    }

    @Test fun websocketKeepaliveIsMaskedControlFrameNotMtProtoData() {
        LocalServer { socket ->
            serveUpgrade(socket)
            val ping = readClientWs(socket)
            assertEquals(9, ping.first); assertEquals(0, ping.second.size)
            socket.getOutputStream().apply { write(wsFrame(10, ByteArray(0))); write(wsFrame(2, byteArrayOf(42))); flush() }
        }.use { server ->
            SessionIo().use { io ->
                WebSocketTransport.upgrade(io.track(Socket("127.0.0.1", server.port)), "localhost", io).use { ws ->
                    val later = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(31)
                    assertTrue(ws.claimKeepAlive(later)); assertFalse(ws.claimKeepAlive(later))
                    ws.keepAlive(); assertArrayEquals(byteArrayOf(42), ws.receive())
                }
            }
            server.assertSuccess()
        }
    }

    private fun serveAnonymousTelegram(socket: Socket, protocol: TransportProtocol, signedDc: Int, requests: AtomicInteger) {
        serveUpgrade(socket)
        val init = readClientWs(socket).second
        assertEquals(64, init.size)
        val decrypt = StreamCipher(init.copyOfRange(8, 40), init.copyOfRange(40, 56))
        val decodedInit = decrypt.update(init)
        assertTrue((56..59).all { decodedInit[it].toInt() and 255 == protocol.tag })
        assertEquals(signedDc, ByteBuffer.wrap(decodedInit, 60, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt())
        val packet = decrypt.update(readClientWs(socket).second)
        val header = if (protocol == TransportProtocol.ABRIDGED) 1 else 4
        val request = packet.copyOfRange(header, packet.size)
        assertArrayEquals(ByteArray(8), request.copyOfRange(0, 8))
        assertEquals(0xbe7e8ef1.toInt(), ByteBuffer.wrap(request, 20, 4).order(ByteOrder.LITTLE_ENDIAN).int)
        val nonce = request.copyOfRange(24, 40); requests.incrementAndGet()
        val body = le(0x05162463) + nonce + ByteArray(16) { 7 } + byteArrayOf(1, 1, 0, 0) + le(0x1cb5c415) + le(0)
        val message = ByteArray(8) + ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(1).array() + le(body.size) + body
        val frame = if (protocol == TransportProtocol.ABRIDGED) byteArrayOf((message.size / 4).toByte()) + message else le(message.size) + message
        val reverse = init.copyOfRange(8, 56).reversedArray()
        socket.getOutputStream().apply { write(wsFrame(2, StreamCipher(reverse.copyOfRange(0, 32), reverse.copyOfRange(32, 48)).update(frame))); flush() }
        socket.getInputStream().read()
    }

    private fun reqPq(port: Int, secretHex: String, protocol: TransportProtocol, dc: Int = 2) {
        val secret = hex(secretHex)
        Socket("127.0.0.1", port).use { client ->
            client.soTimeout = 3000
            val init = clientInit(secret, protocol, -dc)
            val upload = StreamCipher(MessageDigest.getInstance("SHA-256").digest(init.copyOfRange(8, 40) + secret), init.copyOfRange(40, 56)).also { it.skipInit() }
            val nonce = ByteArray(16) { it.toByte() }
            val body = le(0xbe7e8ef1.toInt()) + nonce
            val message = ByteArray(8) + ByteArray(8) + le(body.size) + body
            val packet = if (protocol == TransportProtocol.ABRIDGED) byteArrayOf((message.size / 4).toByte()) + message else le(message.size) + message
            client.getOutputStream().apply { write(init); write(upload.update(packet)); flush() }
            val reverse = init.copyOfRange(8, 56).reversedArray()
            val download = StreamCipher(MessageDigest.getInstance("SHA-256").digest(reverse.copyOfRange(0, 32) + secret), reverse.copyOfRange(32, 48))
            val length = if (protocol == TransportProtocol.ABRIDGED) (download.update(client.getInputStream().exactly(1))[0].toInt() and 127) * 4 else
                ByteBuffer.wrap(download.update(client.getInputStream().exactly(4))).order(ByteOrder.LITTLE_ENDIAN).int
            val response = download.update(client.getInputStream().exactly(length))
            assertEquals(0x05162463, ByteBuffer.wrap(response, 20, 4).order(ByteOrder.LITTLE_ENDIAN).int)
            assertArrayEquals(nonce, response.copyOfRange(24, 40))
        }
    }
    private fun le(value: Int) = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array()
}

internal fun readClientWs(socket: Socket): Pair<Int, ByteArray> {
    val input = socket.getInputStream()
    val first = input.read(); val second = input.read()
    check(first >= 0 && second >= 0 && first and 0x80 != 0 && second and 0x80 != 0)
    val opcode = first and 15
    val size = when (val value = second and 127) {
        126 -> input.exactly(2).fold(0L) { total, byte -> (total shl 8) or (byte.toLong() and 255) }
        127 -> input.exactly(8).fold(0L) { total, byte -> (total shl 8) or (byte.toLong() and 255) }
        else -> value.toLong()
    }
    check(size in 0..MAX_FRAME_BYTES.toLong())
    val mask = input.exactly(4); val payload = input.exactly(size.toInt())
    return opcode to ByteArray(payload.size) { (payload[it].toInt() xor mask[it and 3].toInt()).toByte() }
}
