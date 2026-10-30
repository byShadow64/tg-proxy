package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.io.EOFException
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class SharedHostResolverTest {
    private val address = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))

    @Test fun abandonedUninterruptibleDnsRemainsSharedAndItsCompletedResultIsCached() {
        val started = CountDownLatch(1); val release = CountDownLatch(1); val calls = AtomicInteger()
        val callers = Executors.newFixedThreadPool(2)
        SharedHostResolver({
            calls.incrementAndGet(); started.countDown()
            while (release.count > 0) try { release.await() } catch (_: InterruptedException) { /* Native DNS may ignore interruption. */ }
            listOf(address)
        }).use { resolver ->
            try {
                repeat(8) {
                    val io = SessionIo()
                    val owner = java.util.concurrent.atomic.AtomicReference<Thread>()
                    val abandoned = callers.submit<Boolean> { owner.set(Thread.currentThread()); try { resolver.resolveAll("shared.invalid", io); false } catch (_: EOFException) { true } }
                    assertTrue(started.await(1, TimeUnit.SECONDS))
                    await { owner.get()?.state == Thread.State.TIMED_WAITING }
                    io.close()
                    assertTrue("Client cancellation must be independent of native DNS completion", abandoned.get(1, TimeUnit.SECONDS))
                }
                assertEquals("Canceled waiters must not duplicate a still-running native call", 1, calls.get())
                val io = SessionIo()
                val waiting = callers.submit<List<InetAddress>> { resolver.resolveAll("shared.invalid", io) }
                release.countDown()
                assertEquals(listOf(address), waiting.get(1, TimeUnit.SECONDS)); io.close()
                SessionIo().use { cached -> assertEquals(listOf(address), resolver.resolveAll("shared.invalid", cached)) }
                assertEquals(1, calls.get())
            } finally { release.countDown(); callers.shutdownNow(); callers.awaitTermination(1, TimeUnit.SECONDS) }
        }
    }

    @Test fun timedOutRunningDnsIsSharedButAbandonedQueuedDnsNeverRuns() {
        val entered = CountDownLatch(2); val release = CountDownLatch(1)
        val counts = ConcurrentHashMap<String, AtomicInteger>(); val callers = Executors.newFixedThreadPool(3)
        SharedHostResolver({ host ->
            counts.computeIfAbsent(host) { AtomicInteger() }.incrementAndGet(); entered.countDown()
            while (release.count > 0) try { release.await() } catch (_: InterruptedException) {}
            listOf(address)
        }).use { resolver ->
            val first = SessionIo(); val second = SessionIo(); val queued = SessionIo()
            try {
                val active = listOf("first.invalid" to first, "second.invalid" to second).map { (host, io) ->
                    callers.submit<Boolean> { try { resolver.resolveAll(host, io); false } catch (_: EOFException) { true } catch (_: java.net.SocketTimeoutException) { true } }
                }
                assertTrue(entered.await(1, TimeUnit.SECONDS))
                val pending = callers.submit<Boolean> { try { resolver.resolveAll("queued.invalid", queued); false } catch (_: EOFException) { true } }
                await { "dns" in deadlines(queued) }
                queued.close(); assertTrue(pending.get(1, TimeUnit.SECONDS))
                first.expire(Long.MAX_VALUE); second.close()
                active.forEach { assertTrue(it.get(1, TimeUnit.SECONDS)) }
                assertTrue(first.timedOut); assertEquals(EngineStage.DNS, first.failureStage)
                release.countDown()
                SessionIo().use { next -> assertEquals(listOf(address), resolver.resolveAll("first.invalid", next)) }
                assertEquals(1, counts["first.invalid"]?.get()); assertEquals(1, counts["second.invalid"]?.get())
                assertFalse(counts.containsKey("queued.invalid"))
            } finally { first.close(); second.close(); queued.close(); release.countDown(); callers.shutdownNow(); callers.awaitTermination(1, TimeUnit.SECONDS) }
        }
    }

    companion object {
        private fun await(condition: () -> Boolean) {
            val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(1)
            while (!condition() && System.nanoTime() < until) Thread.sleep(5)
            assertTrue(condition())
        }
    }
}
