package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit

class RouteQualificationTest {
    private val media = ClientHandshake(2, true, TransportProtocol.PADDED_INTERMEDIATE, ByteArray(48))

    @Test fun coldMediaUsesStrictNumericFallbackInsteadOfUnqualifiedFront() {
        val attempted = CopyOnWriteArrayList<DirectRoute>()
        val sent = java.util.concurrent.atomic.AtomicInteger()
        val transport = object : BinaryTransport {
            override fun send(bytes: ByteArray) { sent.incrementAndGet() }
            override fun receive(): ByteArray? = null
            override fun close() {}
        }
        DirectRoutePlanner({ route, _ ->
            attempted += route
            if (route.strategy != DirectStrategy.FRONTED_IP) Thread.sleep(75)
            transport
        }, hedgeMillis = 0).use { planner ->
            val plan = planner.plan(media)
            assertTrue(plan.none { it.strategy == DirectStrategy.FRONTED_IP })
            val numeric = plan.single { it.strategy == DirectStrategy.FIXED_IP }
            assertEquals("149.154.167.220", numeric.host)
            assertEquals("kws2-1.web.telegram.org", numeric.domain)
            SessionIo().use { io ->
                planner.connect(media, io).use { connected ->
                    assertNotEquals("A fast 101 from an unqualified media front must not win", DirectStrategy.FRONTED_IP, connected.route.strategy)
                    assertEquals(0, sent.get())
                    assertTrue(attempted.none { it.strategy == DirectStrategy.FRONTED_IP })
                }
            }
        }
    }

    @Test fun coolingDownAllRoutesFailsClosedInsteadOfImmediatelyRedialingThem() {
        var now = 1L
        DirectRoutePlanner(now = { now }, useRelays = false).use { planner ->
            val candidates = planner.plan(media)
            assertTrue(candidates.isNotEmpty())
            candidates.forEach(planner::fail)
            assertTrue("No known failed endpoint may bypass its circuit breaker", planner.plan(media).isEmpty())
            now += TimeUnit.SECONDS.toNanos(31)
            assertTrue(planner.plan(media).isNotEmpty())
        }
    }

    @Test fun failedFirstBatchUsesOtherCatalogEntriesBeforeAnyCoolingDownEndpoint() {
        DirectRoutePlanner().use { planner ->
            val failed = planner.plan(media)
            assertEquals(4, failed.size)
            failed.forEach(planner::fail)
            val alternatives = planner.plan(media)
            assertEquals(2, alternatives.size)
            assertTrue(alternatives.all { it.strategy == DirectStrategy.RELAY_WSS && it !in failed })
            alternatives.forEach(planner::fail)
            assertTrue(planner.plan(media).isEmpty())
        }
    }

    @Test fun wholeSetupTimeoutCoolsStartedBlackholesButManualCancellationDoesNot() {
        for (cancel in listOf(false, true)) {
            val attempted = CopyOnWriteArrayList<DirectRoute>()
            val failures = CopyOnWriteArrayList<DirectRoute>()
            val ready = java.util.concurrent.CountDownLatch(2)
            DirectRoutePlanner({ route, io ->
                attempted += route; ready.countDown()
                while (!io.closed) Thread.sleep(2)
                throw java.io.EOFException()
            }, setupTimeoutMillis = 150, useRelays = false, hedgeMillis = 0,
                onAttemptFailure = { route, _ -> failures += route }).use { planner ->
                SessionIo().use { io ->
                    val ended = java.util.concurrent.CountDownLatch(1)
                    val thrown = java.util.concurrent.atomic.AtomicReference<Throwable?>()
                    val runner = Thread {
                        try { planner.connect(media, io); thrown.set(AssertionError("Expected setup to end without a transport")) }
                        catch (failure: Throwable) { thrown.set(failure) }
                        finally { ended.countDown() }
                    }.apply { isDaemon = true; start() }
                    assertTrue(ready.await(1, TimeUnit.SECONDS))
                    if (cancel) io.close()
                    assertTrue(ended.await(1, TimeUnit.SECONDS))
                    runner.join(100)
                    if (cancel) assertTrue(thrown.get() is java.io.EOFException)
                    else assertTrue(thrown.get() is java.net.SocketTimeoutException)
                    assertEquals(2, attempted.size)
                    if (cancel) {
                        assertTrue(failures.isEmpty())
                        assertEquals(attempted.toSet(), planner.plan(media).toSet())
                    } else {
                        assertEquals(attempted.toSet(), failures.toSet())
                        assertTrue(planner.plan(media).isEmpty())
                    }
                }
            }
        }
    }

    @Test fun executorQueueTimeoutDoesNotBlacklistAnEndpointThatWasNeverDialed() {
        val started = java.util.concurrent.CountDownLatch(8)
        val release = java.util.concurrent.CountDownLatch(1)
        val active = java.util.concurrent.atomic.AtomicInteger()
        val attempted = CopyOnWriteArrayList<DirectRoute>()
        val failures = CopyOnWriteArrayList<DirectRoute>()
        val callers = java.util.concurrent.Executors.newFixedThreadPool(4)
        DirectRoutePlanner({ route, _ ->
            attempted += route; active.incrementAndGet(); started.countDown()
            // Models native DNS that does not return immediately when interrupted.
            try {
                while (release.count > 0) {
                    try { release.await() } catch (_: InterruptedException) {}
                }
                throw java.io.EOFException()
            } finally { active.decrementAndGet() }
        }, setupTimeoutMillis = 500, useRelays = false, hedgeMillis = 0,
            onAttemptFailure = { route, _ -> failures += route }).use { planner ->
            try {
                val occupied = (1..4).map { dc -> callers.submit {
                    SessionIo().use { io ->
                        try { planner.connect(media.copy(dc = dc), io); fail() }
                        catch (_: java.net.SocketTimeoutException) {}
                    }
                } }
                assertTrue(started.await(2, TimeUnit.SECONDS))
                occupied.forEach { it.get(2, TimeUnit.SECONDS) }
                assertEquals(8, active.get())
                val queued = media.copy(dc = 5)
                val before = planner.plan(queued).toSet()
                SessionIo().use { io ->
                    try { planner.connect(queued, io); fail() }
                    catch (_: java.net.SocketTimeoutException) {}
                }
                assertTrue(attempted.none { it.dc == 5 })
                assertTrue(failures.none { it.dc == 5 })
                assertEquals(before, planner.plan(queued).toSet())
            } finally {
                release.countDown(); callers.shutdownNow()
                callers.awaitTermination(2, TimeUnit.SECONDS)
                await { active.get() == 0 }
            }
        }
    }

    @Test fun successfulRaceDoesNotBlacklistItsCanceledCandidates() {
        val failed = CopyOnWriteArrayList<DirectRoute>()
        val blocked = java.util.concurrent.CountDownLatch(1)
        val transport = object : BinaryTransport {
            override fun send(bytes: ByteArray) {}
            override fun receive(): ByteArray? = null
            override fun close() {}
        }
        DirectRoutePlanner({ route, child ->
            if (route.strategy == DirectStrategy.OFFICIAL_DNS) {
                blocked.countDown()
                while (!child.closed) Thread.sleep(2)
                throw java.io.EOFException()
            }
            assertTrue(blocked.await(1, TimeUnit.SECONDS))
            transport
        }, setupTimeoutMillis = 500, useRelays = false, hedgeMillis = 0,
            onAttemptFailure = { route, _ -> failed += route }).use { planner ->
            val before = planner.plan(media).toSet()
            SessionIo().use { io -> planner.connect(media, io).close() }
            assertEquals(before, planner.plan(media).toSet())
            assertTrue(failed.isEmpty())
        }
    }

    @Test fun setupFailureReportsOnlyCandidateAndStageAndNeverCanceledLoser() {
        val failures = CopyOnWriteArrayList<Pair<DirectRoute, EngineStage?>>()
        val reported = java.util.concurrent.CountDownLatch(1)
        val transport = object : BinaryTransport {
            override fun send(bytes: ByteArray) {}
            override fun receive(): ByteArray? = null
            override fun close() {}
        }
        DirectRoutePlanner({ route, io ->
            if (route.strategy == DirectStrategy.OFFICIAL_DNS) io.operation("dns", 100) { throw java.net.UnknownHostException() }
            else if (route.strategy == DirectStrategy.RELAY_WSS) { assertTrue(reported.await(1, TimeUnit.SECONDS)); transport }
            else { while (!io.closed) Thread.sleep(5); throw java.io.EOFException() }
        }, hedgeMillis = 0, onAttemptFailure = { route, stage -> failures += route to stage; reported.countDown() }).use { planner ->
            SessionIo().use { io -> planner.connect(media, io).close() }
            assertEquals(1, failures.size)
            assertEquals(DirectStrategy.OFFICIAL_DNS, failures.single().first.strategy)
            assertEquals(EngineStage.DNS, failures.single().second)
        }
    }
}
