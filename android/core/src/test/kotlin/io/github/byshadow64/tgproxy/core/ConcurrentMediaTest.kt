package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.net.Socket
import java.security.MessageDigest
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class ConcurrentMediaTest {
    @Test fun twentyFourParallelMediaAndChatSessionsCoalescePacketsAndPreserveDownstreamQuickAck() {
        val count = 24
        val token = "independent-local-fixture-token-".repeat(2)
        val secretHex = "13".repeat(16)
        val secret = hex(secretHex)
        val failures = CopyOnWriteArrayList<Throwable>()
        val events = CopyOnWriteArrayList<EngineEvent>()
        val completed = CountDownLatch(count)
        val handlers = Executors.newFixedThreadPool(count)
        val clients = Executors.newFixedThreadPool(count)
        val server = TlsFixture.serverContext.serverSocketFactory.createServerSocket(0, count, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)))
        val acceptor = Thread {
            try {
                repeat(count) {
                    val socket = server.accept()
                    handlers.execute {
                        try { socket.use { peer ->
                            peer.soTimeout = 8_000
                            assertEquals(token, readHelper(peer).toString(Charsets.UTF_8))
                            assertTrue(readHelper(peer).toString(Charsets.US_ASCII).matches(Regex("kws[24](?:-1)?\\.web\\.telegram\\.org")))
                            writeHelper(peer, "OK".toByteArray())
                            val relay = readHelper(peer)
                            val up = StreamCipher(relay.copyOfRange(8, 40), relay.copyOfRange(40, 56))
                            val initPlain = up.update(relay)
                            val packet = up.update(readHelper(peer))
                            val abridged = initPlain[56].toInt() and 255 == 0xef
                            val header = if (abridged) 1 else 4
                            val length = if (abridged) (packet[0].toInt() and 127) * 4 else
                                (packet[0].toInt() and 255) or ((packet[1].toInt() and 255) shl 8) or ((packet[2].toInt() and 255) shl 16) or ((packet[3].toInt() and 127) shl 24)
                            assertEquals(header + length, packet.size)
                            assertTrue(packet.size in listOf(17, 20, 35))
                            val reverse = relay.copyOfRange(8, 56).reversedArray()
                            val down = StreamCipher(reverse.copyOfRange(0, 32), reverse.copyOfRange(32, 48))
                            val reply = byteArrayOf(0x80.toByte(), 5, 6, 7) + ByteArray(64) { it.toByte() }
                            val encrypted = down.update(reply)
                            writeHelper(peer, encrypted.copyOfRange(0, 4)); writeHelper(peer, encrypted.copyOfRange(4, encrypted.size))
                            peer.getInputStream().read()
                        } } catch (failure: Throwable) { failures += failure }
                        finally { completed.countDown() }
                    }
                }
            } catch (failure: Throwable) { failures += failure }
        }.apply { isDaemon = true; start() }
        val port = freePort()
        try {
            ProxyEngine(EngineConfig(port, secretHex, HelperSettings("127.0.0.1", server.localPort, TlsFixture.pin, token)), events::add).use { engine ->
                engine.start()
                val start = CountDownLatch(1)
                val futures = (0 until count).map { index -> clients.submit {
                    start.await()
                    Socket("127.0.0.1", port).use { client ->
                        client.soTimeout = 10_000
                        val protocol = TransportProtocol.entries[index % 3]
                        val init = clientInit(secret, protocol, if (index % 2 == 0) -2 else 4)
                        val up = StreamCipher(MessageDigest.getInstance("SHA-256").digest(init.copyOfRange(8, 40) + secret), init.copyOfRange(40, 56)).also { it.skipInit() }
                        val payload = ByteArray(16) { index.toByte() } + if (protocol == TransportProtocol.PADDED_INTERMEDIATE) ByteArray(15) { 42 } else ByteArray(0)
                        val packet = if (protocol == TransportProtocol.ABRIDGED) byteArrayOf(4) + payload else
                            byteArrayOf(payload.size.toByte(), 0, 0, 0x80.toByte()) + payload
                        val encrypted = up.update(packet)
                        client.getOutputStream().apply {
                            write(init); write(encrypted, 0, 1); flush(); Thread.sleep(3)
                            write(encrypted, 1, 2); flush(); Thread.sleep(3)
                            write(encrypted, 3, encrypted.size - 3); flush()
                        }
                        val reverse = init.copyOfRange(8, 56).reversedArray()
                        val down = StreamCipher(MessageDigest.getInstance("SHA-256").digest(reverse.copyOfRange(0, 32) + secret), reverse.copyOfRange(32, 48))
                        assertArrayEquals(byteArrayOf(0x80.toByte(), 5, 6, 7) + ByteArray(64) { it.toByte() }, down.update(client.getInputStream().exactly(68)))
                    }
                } }
                start.countDown(); futures.forEach { it.get(15, TimeUnit.SECONDS) }
                assertTrue(completed.await(5, TimeUnit.SECONDS))
                if (failures.isNotEmpty()) throw AssertionError("Concurrent local helper fixture failed", failures.first())
                await { engine.snapshot().activeConnections == 0 && MsgSplitter.sharedBudget.used == 0L }
                assertEquals(count.toLong(), engine.snapshot().helperConnections)
                assertFalse(events.any { it.code == EventCode.CONNECTION_LIMIT || it.code == EventCode.TIMEOUT })
            }
        } finally {
            server.close(); clients.shutdownNow(); handlers.shutdownNow(); acceptor.join(1_000)
            clients.awaitTermination(2, TimeUnit.SECONDS); handlers.awaitTermination(2, TimeUnit.SECONDS)
        }
    }
}
