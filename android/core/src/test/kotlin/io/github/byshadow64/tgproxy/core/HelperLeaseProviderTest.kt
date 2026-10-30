package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class HelperLeaseProviderTest {
    @Test fun freshSettingsApplyOnlyToNewConnectionsAndPreserveExistingFlow() {
        val firstReady = CountDownLatch(1); val secondReady = CountDownLatch(1); val sendFirst = CountDownLatch(1)
        val token1 = "first-local-lease-".repeat(3); val token2 = "second-local-lease-".repeat(3)
        val calls = AtomicInteger()
        TlsFixture.server { peer ->
            assertEquals(token1, readHelper(peer).toString(Charsets.UTF_8)); readHelper(peer); writeHelper(peer, "OK".toByteArray())
            val relay = readHelper(peer); firstReady.countDown(); sendFirst.await()
            val reverse = relay.copyOfRange(8, 56).reversedArray()
            writeHelper(peer, StreamCipher(reverse.copyOfRange(0, 32), reverse.copyOfRange(32, 48)).update(byteArrayOf(1, 2, 3, 4)))
            peer.getInputStream().read()
        }.use { first ->
            TlsFixture.server { peer ->
                assertEquals(token2, readHelper(peer).toString(Charsets.UTF_8)); readHelper(peer); writeHelper(peer, "OK".toByteArray())
                assertEquals(64, readHelper(peer).size); secondReady.countDown(); peer.getInputStream().read()
            }.use { second ->
                val provider = HelperConnectionProvider {
                    val number = calls.incrementAndGet()
                    HelperSettings("127.0.0.1", if (number == 1) first.port else second.port, TlsFixture.pin, if (number == 1) token1 else token2)
                }
                val port = freePort(); val secret = "28".repeat(16)
                val config = EngineConfig(port, secret, HelperSettings("127.0.0.1", 8444, "00".repeat(32), ""))
                ProxyEngine(config, provider).use { engine ->
                    engine.start()
                    Socket("127.0.0.1", port).use { a ->
                        a.soTimeout = 2000; a.getOutputStream().write(clientInit(hex(secret), TransportProtocol.INTERMEDIATE, 2))
                        assertTrue(firstReady.await(2, TimeUnit.SECONDS))
                        Socket("127.0.0.1", port).use { b ->
                            b.getOutputStream().write(clientInit(hex(secret), TransportProtocol.INTERMEDIATE, 2))
                            assertTrue(secondReady.await(2, TimeUnit.SECONDS)); assertEquals(2, calls.get())
                            sendFirst.countDown(); assertEquals(4, a.getInputStream().exactly(4).size)
                            assertEquals(2, engine.snapshot().activeConnections)
                            assertEquals("", config.helper!!.token)
                        }
                    }
                }
                second.assertSuccess()
            }
            first.assertSuccess()
        }
    }

    @Test fun providerCannotRedirectConfiguredHostOrFallBackToDirect() {
        val events = java.util.concurrent.CopyOnWriteArrayList<EngineEvent>()
        val port = freePort()
        val config = EngineConfig(port, "29".repeat(16), HelperSettings("127.0.0.1", 8444, "00".repeat(32), ""))
        ProxyEngine(config, HelperConnectionProvider { HelperSettings("192.0.2.1", 8444, "00".repeat(32), "unusable-test-lease-".repeat(3)) }, events::add).use { engine ->
            engine.start()
            Socket("127.0.0.1", port).use { client ->
                client.soTimeout = 1000; client.getOutputStream().write(clientInit(hex(config.secretHex), TransportProtocol.INTERMEDIATE, 2))
                assertEquals(-1, client.getInputStream().read())
            }
            await { events.any { it.code == EventCode.HELPER_REJECTED } }
            assertEquals(0L, engine.snapshot().directConnections); assertEquals(0L, engine.snapshot().relayConnections)
        }
    }

    @Test fun clientEofCancelsPendingLeaseBeforeAnyHelperConnection() {
        val entered = CountDownLatch(1); val cancelled = CountDownLatch(1)
        val port = freePort()
        val config = EngineConfig(port, "30".repeat(16), HelperSettings("127.0.0.1", 8444, "00".repeat(32), ""))
        val provider = HelperConnectionProvider { stop ->
            entered.countDown()
            while (!stop()) Thread.sleep(5)
            cancelled.countDown(); throw java.io.EOFException()
        }
        ProxyEngine(config, provider).use { engine ->
            engine.start()
            Socket("127.0.0.1", port).use { client ->
                client.getOutputStream().write(clientInit(hex(config.secretHex), TransportProtocol.PADDED_INTERMEDIATE, 2))
                assertTrue(entered.await(1, TimeUnit.SECONDS))
            }
            assertTrue(cancelled.await(1, TimeUnit.SECONDS)); await { engine.snapshot().activeConnections == 0 }
        }
    }
}
