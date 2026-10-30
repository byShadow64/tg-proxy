package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class RouteRaceTest {
    private val handshake = ClientHandshake(2, true, TransportProtocol.PADDED_INTERMEDIATE, ByteArray(48))
    private fun blackhole(io: SessionIo): BinaryTransport { while (!io.closed) Thread.sleep(5); throw java.io.EOFException() }

    @Test fun wholeSetupBudgetClosesAllFourAttemptsInsteadOfMultiplyingTimeouts() {
        val children = CopyOnWriteArrayList<SessionIo>()
        val active = AtomicInteger()
        DirectRoutePlanner({ _, io -> children += io; active.incrementAndGet(); try { blackhole(io) } finally { active.decrementAndGet() } }, setupTimeoutMillis = 250, hedgeMillis = 0).use { planner ->
            SessionIo().use { io ->
                val began = System.nanoTime()
                try { planner.connect(handshake, io); fail() } catch (_: java.net.SocketTimeoutException) {}
                assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - began) < 1000)
                assertEquals(4, children.size)
                assertTrue(children.all { it.closed })
                await { active.get() == 0 }
            }
        }
    }

    @Test fun secureRelayWinsBlockedDirectAndSetupSendsNoClientPayload() {
        val children = CopyOnWriteArrayList<SessionIo>()
        val sends = AtomicInteger()
        val fake = object : BinaryTransport { override fun send(bytes: ByteArray) { sends.incrementAndGet() }; override fun receive(): ByteArray? = null; override fun close() {} }
        DirectRoutePlanner({ route, io -> children += io; if (route.strategy == DirectStrategy.RELAY_WSS) fake else blackhole(io) }, setupTimeoutMillis = 1000, hedgeMillis = 0).use { planner ->
            SessionIo().use { io ->
                planner.connect(handshake, io).use { result ->
                    assertEquals(DirectStrategy.RELAY_WSS, result.route.strategy)
                    assertEquals(0, sends.get())
                    assertTrue(children.count { !it.closed } <= 1)
                    result.confirmedResponse()
                    assertEquals(result.route, planner.plan(handshake).first())
                }
            }
        }
    }

    @Test fun relayHostnameMappingPreservesDcMediaAndCatalogIsSmallAndTlsOnly() {
        DirectRoutePlanner().use { planner ->
            assertEquals(4, WssRelayCatalog.domains.size)
            for (dc in listOf(1, 2, 3, 4, 5, 203)) for (media in listOf(false, true)) {
                val route = handshake.copy(dc = dc, media = media)
                val plan = planner.plan(route)
                assertTrue(plan.size <= 4)
                assertEquals(2, plan.count { it.strategy == DirectStrategy.RELAY_WSS })
                plan.filter { it.strategy == DirectStrategy.RELAY_WSS }.forEach {
                    assertEquals(dc, it.dc); assertEquals(media, it.media)
                    assertTrue(it.domain.startsWith("kws$dc.")); assertEquals(it.domain, it.host)
                    assertTrue(WssRelayCatalog.domains.any { base -> it.domain == "kws$dc.$base" })
                }
            }
        }
    }

    @Test fun unreachableBurstIsBoundedAndReleasesEveryLocalConnection() {
        val activeDials = AtomicInteger(); val peakDials = AtomicInteger()
        DirectRoutePlanner({ _, child ->
            val active = activeDials.incrementAndGet(); peakDials.updateAndGet { maxOf(it, active) }
            try { blackhole(child) } finally { activeDials.decrementAndGet() }
        }, setupTimeoutMillis = 200, hedgeMillis = 0).use { planner ->
            val port = freePort()
            val connector: (ClientHandshake, SessionIo) -> BinaryTransport = { h, io -> planner.connect(h, io) }
            ProxyEngine(EngineConfig(port, "24".repeat(16)), connector).use { engine ->
                engine.start()
                val start = CountDownLatch(1)
                val callers = Executors.newFixedThreadPool(24)
                try {
                    val futures = (0 until 24).map { callers.submit {
                        start.await()
                        Socket("127.0.0.1", port).use { client ->
                            client.soTimeout = 3000
                            client.getOutputStream().write(clientInit(hex("24".repeat(16)), TransportProtocol.INTERMEDIATE, 2))
                            assertEquals(-1, client.getInputStream().read())
                        }
                    } }
                    start.countDown(); futures.forEach { it.get(4, TimeUnit.SECONDS) }
                    await { engine.snapshot().activeConnections == 0 && activeDials.get() == 0 }
                    assertTrue(peakDials.get() <= 8)
                    assertEquals(24L, engine.snapshot().totalConnections)
                } finally { callers.shutdownNow(); callers.awaitTermination(1, TimeUnit.SECONDS) }
            }
        }
    }

    @Test fun dnsPrefersUsableIpv4OverFirstIpv6AndKeepsBothFamilies() {
        val v6 = java.net.InetAddress.getByName("2001:db8::1")
        val v4 = java.net.InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        val addresses = BoundedDns.preferIpv4(listOf(v6, v4, v4))
        assertEquals(listOf(v4, v6), addresses)
    }
}
