package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class NetworkRecoveryTest {
    private val oldAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val newAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 2))

    @Test fun changedNetworkDropsDnsCacheBeforeItsNormalTtl() {
        val calls = AtomicInteger()
        SharedHostResolver({ if (calls.incrementAndGet() == 1) listOf(oldAddress) else listOf(newAddress) }).use { resolver ->
            SessionIo().use { assertEquals(listOf(oldAddress), resolver.resolveAll("network.invalid", it)) }
            resolver.networkChanged()
            SessionIo().use { assertEquals(listOf(newAddress), resolver.resolveAll("network.invalid", it)) }
            assertEquals(2, calls.get())
        }
    }

    @Test fun lateDnsFromOldNetworkCannotBeSharedOrRefillReplacementCache() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
        val caller = Executors.newSingleThreadExecutor()
        SharedHostResolver({
            if (calls.incrementAndGet() == 1) {
                entered.countDown()
                while (release.count > 0) try { release.await() } catch (_: InterruptedException) {}
                listOf(oldAddress)
            } else listOf(newAddress)
        }).use { resolver ->
            try {
                val old = caller.submit<List<InetAddress>> { SessionIo().use { resolver.resolveAll("network.invalid", it) } }
                assertTrue(entered.await(1, TimeUnit.SECONDS))
                resolver.networkChanged()
                SessionIo().use { assertEquals(listOf(newAddress), resolver.resolveAll("network.invalid", it, 200)) }
                release.countDown()
                assertEquals(listOf(oldAddress), old.get(1, TimeUnit.SECONDS))
                SessionIo().use { assertEquals(listOf(newAddress), resolver.resolveAll("network.invalid", it)) }
                assertEquals(2, calls.get())
            } finally { release.countDown(); caller.shutdownNow(); caller.awaitTermination(1, TimeUnit.SECONDS) }
        }
    }

    @Test fun changedNetworkClearsRouteCooldownAndDiscardsLateOldRouteFeedback() {
        val handshake = ClientHandshake(2, true, TransportProtocol.INTERMEDIATE, ByteArray(48))
        val transport = object : BinaryTransport {
            override fun send(bytes: ByteArray) {}
            override fun receive(): ByteArray? = null
            override fun close() {}
        }
        DirectRoutePlanner({ route, _ ->
            if (route.strategy == DirectStrategy.OFFICIAL_DNS) throw java.net.ConnectException()
            transport
        }, useRelays = false).use { planner ->
            SessionIo().use { io ->
                planner.connect(handshake, io).use { old ->
                    assertEquals(DirectStrategy.FIXED_IP, old.route.strategy)
                    assertTrue(planner.plan(handshake).none { it.strategy == DirectStrategy.OFFICIAL_DNS })
                    planner.networkChanged()
                    old.confirmedResponse()
                    assertEquals(DirectStrategy.OFFICIAL_DNS, planner.plan(handshake).first().strategy)
                    old.failedFirstReply()
                    assertTrue(planner.plan(handshake).contains(old.route))
                }
            }
        }
    }

    @Test fun changedNetworkClosesStalledSessionsButKeepsListenerPortSecretAndLifecycle() {
        val port = freePort()
        val secret = "53".repeat(16)
        val events = CopyOnWriteArrayList<EngineEvent>()
        val connector: (ClientHandshake, SessionIo) -> BinaryTransport = { _, io ->
            object : BinaryTransport {
                override fun send(bytes: ByteArray) {}
                override fun receive(): ByteArray? { while (!io.closed) Thread.sleep(5); return null }
                override fun close() { io.close() }
            }
        }
        ProxyEngine(EngineConfig(port, secret), connector, events::add).use { engine ->
            engine.start()
            Socket("127.0.0.1", port).use { old ->
                old.soTimeout = 1_000
                old.getOutputStream().write(clientInit(hex(secret), TransportProtocol.INTERMEDIATE, 2))
                await { events.count { it.code == EventCode.ROUTE_CONNECTED } == 1 }
                engine.networkChanged()
                assertEquals(-1, old.getInputStream().read())
                await { engine.snapshot().activeConnections == 0 }
                assertEquals(EngineState.RUNNING, engine.snapshot().state)
                assertEquals(port, engine.snapshot().port)
                Socket("127.0.0.1", port).use { next ->
                    next.getOutputStream().write(clientInit(hex(secret), TransportProtocol.INTERMEDIATE, 2))
                    await { events.count { it.code == EventCode.ROUTE_CONNECTED } == 2 }
                    assertEquals(1, engine.snapshot().activeConnections)
                }
                assertEquals(1, events.count { it.code == EventCode.STARTED })
                assertEquals(0, events.count { it.code == EventCode.STOPPED })
                assertFalse(events.any { it.code == EventCode.INVALID_HANDSHAKE })
            }
        }
    }
}
