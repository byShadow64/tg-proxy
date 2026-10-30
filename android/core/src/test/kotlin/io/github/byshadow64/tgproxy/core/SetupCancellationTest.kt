package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class SetupCancellationTest {
    @Test fun stopUsesOneShortJoinBudgetWhenUpstreamCodeIgnoresInterruption() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val discarded = CountDownLatch(1)
        val events = java.util.concurrent.CopyOnWriteArrayList<EngineEvent>()
        val lateSends = java.util.concurrent.atomic.AtomicInteger()
        val ownedIo = java.util.concurrent.atomic.AtomicReference<SessionIo>()
        val port = freePort()
        val connector: (ClientHandshake, SessionIo) -> BinaryTransport = { _, io ->
            ownedIo.set(io); entered.countDown()
            // Native DNS and some third-party I/O can keep running after shutdownNow().
            while (release.count > 0) try { release.await() } catch (_: InterruptedException) {}
            object : BinaryTransport {
                override fun send(bytes: ByteArray) { lateSends.incrementAndGet() }
                override fun receive(): ByteArray? = null
                override fun close() { discarded.countDown() }
            }
        }
        ProxyEngine(EngineConfig(port, "28".repeat(16), maxConnections = 1), connector, events::add).use { engine ->
            try {
                engine.start()
                Socket("127.0.0.1", port).use { client ->
                    client.soTimeout = 1_000
                    client.getOutputStream().write(clientInit(hex("28".repeat(16)), TransportProtocol.INTERMEDIATE, 2))
                    assertTrue(entered.await(1, TimeUnit.SECONDS))
                    val start = System.nanoTime()
                    engine.stop()
                    assertTrue("Stop must not accumulate one-second waits on the Android main thread",
                        TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 900)
                    assertTrue(ownedIo.get().closed)
                    assertEquals(-1, client.getInputStream().read())
                    assertEquals(0, engine.snapshot().activeConnections)
                    assertEquals(EngineState.STOPPED, engine.snapshot().state)
                }
                // The lingering worker no longer owns the listener or a connection slot.
                engine.start()
                Socket("127.0.0.1", port).use {
                    await { engine.snapshot().activeConnections == 1 }
                    release.countDown()
                    assertTrue(discarded.await(1, TimeUnit.SECONDS))
                    assertEquals(0, lateSends.get())
                    assertFalse(events.any { event -> event.code == EventCode.ROUTE_CONNECTED })
                    assertEquals(EngineState.RUNNING, engine.snapshot().state)
                    assertEquals(1, engine.snapshot().activeConnections)
                }
            } finally {
                release.countDown()
                assertTrue(discarded.await(1, TimeUnit.SECONDS))
            }
        }
    }

    @Test fun cachedUpstreamThatClosesBeforeAnyReplyIsInvalidatedWithoutReplayingPayload() {
        val handshake = ClientHandshake(2, false, TransportProtocol.INTERMEDIATE, ByteArray(48))
        val sent = java.util.concurrent.CopyOnWriteArrayList<Int>()
        val closedUpstream = object : BinaryTransport {
            override fun send(bytes: ByteArray) { sent += bytes.size }
            override fun receive(): ByteArray? = null
            override fun close() {}
        }
        DirectRoutePlanner({ _, _ -> closedUpstream }).use { planner ->
            val oldPreference = planner.plan(handshake).first()
            planner.confirm(oldPreference)
            val port = freePort()
            val events = java.util.concurrent.CopyOnWriteArrayList<EngineEvent>()
            val connector: (ClientHandshake, SessionIo) -> BinaryTransport = { h, io -> planner.connect(h, io) }
            ProxyEngine(EngineConfig(port, "25".repeat(16)), connector, events::add).use { engine ->
                engine.start()
                Socket("127.0.0.1", port).use { client ->
                    client.soTimeout = 1000
                    client.getOutputStream().write(clientInit(hex("25".repeat(16)), TransportProtocol.INTERMEDIATE, 2))
                    assertEquals(-1, client.getInputStream().read())
                }
                assertFalse(planner.plan(handshake).contains(oldPreference))
                assertEquals(listOf(64), sent)
                val failure = events.single { it.code == EventCode.UPSTREAM_UNAVAILABLE }
                assertEquals(EngineStage.FIRST_REPLY, failure.stage)
                assertEquals(2, failure.dc); assertFalse(failure.media)
                assertEquals(RouteStrategy.FIXED_IP, failure.routeStrategy)
            }
        }
    }

    @Test fun clientDisconnectDuringUpstreamSetupReleasesSlotAndPendingSocket() {
        val dialing = CountDownLatch(1)
        val peerClosed = CountDownLatch(1)
        LocalServer { remote ->
            while (remote.getInputStream().read() >= 0) { }
            peerClosed.countDown()
        }.use { server ->
            val port = freePort()
            val connector: (ClientHandshake, SessionIo) -> BinaryTransport = { _, io ->
                val pending = io.track(Socket("127.0.0.1", server.port))
                dialing.countDown()
                io.operation("tls", HANDSHAKE_TIMEOUT_MS, pending) { pending.getInputStream().read() }
                throw java.io.EOFException()
            }
            ProxyEngine(EngineConfig(port, "23".repeat(16), maxConnections = 1), connector).use { engine ->
                engine.start()
                Socket("127.0.0.1", port).use { client ->
                    client.getOutputStream().write(clientInit(hex("23".repeat(16)), TransportProtocol.PADDED_INTERMEDIATE, 2))
                    assertTrue(dialing.await(1, TimeUnit.SECONDS))
                }
                assertTrue("The peer's disconnect must abort its pending upstream dial", peerClosed.await(1, TimeUnit.SECONDS))
                await { engine.snapshot().activeConnections == 0 }
            }
            server.assertSuccess()
        }
    }
}
