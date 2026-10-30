package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList

class EngineLifecycleTest {
    @Test fun activeListenerCannotBeDuplicatedAndStoppedAcceptedConnectionAllowsPortReuse() {
        val port = freePort()
        val config = EngineConfig(port, "06".repeat(16))
        ProxyEngine(config).use { first ->
            first.start()
            ProxyEngine(config).use { duplicate ->
                try { duplicate.start(); fail() } catch (error: EngineException) {
                    assertEquals(EngineFailureCode.PORT_UNAVAILABLE, error.code)
                }
            }
            Socket("127.0.0.1", port).use { client ->
                client.soTimeout = 2_000
                await { first.snapshot().activeConnections == 1 }
                first.stop()
                assertEquals(-1, client.getInputStream().read())
                java.net.ServerSocket().use { rebound ->
                    rebound.reuseAddress = true
                    rebound.bind(java.net.InetSocketAddress("127.0.0.1", port))
                    assertTrue(rebound.isBound)
                }
                first.start()
                assertEquals(EngineState.RUNNING, first.snapshot().state)
            }
        }
    }

    @Test fun stopClosesPendingHandshakeAndAllowsRestart() {
        val port = freePort()
        val events = CopyOnWriteArrayList<EngineEvent>()
        val engine = ProxyEngine(EngineConfig(port, "01".repeat(16)), events::add)
        try {
            repeat(3) {
                engine.start()
                val client = Socket("127.0.0.1", port).apply { soTimeout = 2_000 }
                await { engine.snapshot().activeConnections == 1 }
                assertEquals(EngineState.RUNNING, engine.snapshot().state)
                engine.stop()
                assertEquals(-1, client.getInputStream().read())
                client.close()
                assertEquals(EngineState.STOPPED, engine.snapshot().state)
                assertEquals(0, engine.snapshot().activeConnections)
            }
            assertEquals(3, events.count { it.code == EventCode.STARTED })
        } finally { engine.stop() }
    }

    @Test fun connectionLimitAndMalformedInitAreHandledLocally() {
        val events = CopyOnWriteArrayList<EngineEvent>()
        val port = freePort()
        ProxyEngine(EngineConfig(port, "02".repeat(16), maxConnections = 1), events::add).use { engine ->
            engine.start()
            Socket("127.0.0.1", port).use { first ->
                await { engine.snapshot().activeConnections == 1 }
                Socket("127.0.0.1", port).use { second ->
                    second.soTimeout = 2_000
                    assertEquals(-1, second.getInputStream().read())
                }
                first.getOutputStream().write(ByteArray(64))
                await { engine.snapshot().activeConnections == 0 }
                assertTrue(events.any { it.code == EventCode.CONNECTION_LIMIT })
                assertTrue(events.any { it.code == EventCode.INVALID_HANDSHAKE })
            }
        }
    }

    @Test fun unsupportedDcNeverOpensUpstream() {
        val events = CopyOnWriteArrayList<EngineEvent>()
        val port = freePort()
        val secret = "03".repeat(16)
        ProxyEngine(EngineConfig(port, secret), events::add).use { engine ->
            engine.start()
            Socket("127.0.0.1", port).use { client ->
                client.soTimeout = 2_000
                client.getOutputStream().write(clientInit(hex(secret), TransportProtocol.INTERMEDIATE, 10002))
                assertEquals(-1, client.getInputStream().read())
                await { events.any { it.code == EventCode.UNSUPPORTED_DC } }
                assertFalse(events.any { it.code == EventCode.ROUTE_CONNECTED })
            }
        }
    }

    @Test fun invalidConfigurationHasOnlySafePublicError() {
        val credential = "PRIVATE_TEST_CREDENTIAL"
        val config = EngineConfig(secretHex = credential)
        assertFalse(config.toString().contains(credential))
        try { ProxyEngine(config).start(); fail() } catch (error: EngineException) {
            assertEquals(EngineFailureCode.INVALID_CONFIGURATION, error.code)
            assertEquals("INVALID_CONFIGURATION", error.message)
            assertNull(error.cause)
        }
        assertFalse(HelperSettings("local", fingerprintHex = credential, token = credential).toString().contains(credential))
    }

    @Test fun watchdogClosesBlockingOperationAndEveryTrackedSocket() {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            Socket("127.0.0.1", server.localPort).use { peer ->
                val io = SessionIo()
                io.track(server.accept())
                val completed = java.util.concurrent.CountDownLatch(1)
                val worker = Thread {
                    try { io.operation("blocked", 1) { io.track(Socket()).close(); Thread.sleep(10_000) } }
                    catch (_: Exception) {} finally { completed.countDown() }
                }
                worker.isDaemon = true; worker.start()
                await { worker.state == Thread.State.TIMED_WAITING }
                io.expire(Long.MAX_VALUE)
                assertTrue(io.timedOut)
                peer.soTimeout = 1_000
                assertEquals(-1, peer.getInputStream().read())
                worker.interrupt()
                assertTrue(completed.await(1, java.util.concurrent.TimeUnit.SECONDS))
                assertTrue(io.closed)
            }
        }
    }
}

internal fun freePort(): Int = ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { it.localPort }
internal fun await(predicate: () -> Boolean) {
    val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(3)
    while (!predicate()) { if (System.nanoTime() > deadline) throw AssertionError("Condition timed out"); Thread.sleep(10) }
}
