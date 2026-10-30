package io.github.byshadow64.tgproxy.core

import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Callable
import java.util.concurrent.FutureTask
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

internal enum class DirectStrategy { OFFICIAL_DNS, FIXED_IP, FRONTED_IP, RELAY_WSS }
internal data class DirectRoute(val dc: Int, val media: Boolean, val domain: String, val host: String, val strategy: DirectStrategy)

/** Only authenticated setup races; client init/payload is sent once to the selected winner. */
internal class RoutedTransport(val delegate: BinaryTransport, val route: DirectRoute, private val planner: DirectRoutePlanner) : BinaryTransport {
    fun confirmedResponse() = planner.confirm(route)
    fun failedFirstReply() = planner.fail(route)
    override fun send(bytes: ByteArray) = delegate.send(bytes)
    override fun receive() = delegate.receive()
    override fun claimKeepAlive(nowNanos: Long) = delegate.claimKeepAlive(nowNanos)
    override fun keepAlive() = delegate.keepAlive()
    override fun close() = delegate.close()
}

internal class DirectRoutePlanner(
    connector: ((DirectRoute, SessionIo) -> BinaryTransport)? = null,
    private val now: () -> Long = System::nanoTime,
    private val setupTimeoutMillis: Long = 8_000,
    private val useRelays: Boolean = true,
    private val hedgeMillis: Long = 150,
    private val onAttemptFailure: (DirectRoute, EngineStage?) -> Unit = { _, _ -> },
) : AutoCloseable {
    private val connectRoute = connector ?: { route: DirectRoute, io: SessionIo ->
        WebSocketTransport.connect(route.host, route.domain, io, sni = if (route.strategy == DirectStrategy.FRONTED_IP) "sprinthost.ru" else null)
    }
    private val preferred = mutableMapOf<Pair<Int, Boolean>, DirectRoute>()
    private val failedUntil = mutableMapOf<DirectRoute, Long>()
    private var relayOffset = 0
    private val executor by lazy {
        ThreadPoolExecutor(8, 8, 30, TimeUnit.SECONDS, ArrayBlockingQueue(256), { task ->
            Thread(task, "tgproxy-dial").apply { isDaemon = true }
        }, ThreadPoolExecutor.AbortPolicy()).apply { allowCoreThreadTimeOut(true) }
    }
    private class Attempt(val route: DirectRoute, val io: SessionIo) {
        val transport = AtomicReference<BinaryTransport?>()
        @Volatile var started = false
        var failureReported = false // Owned by the connect loop, never by the dial worker.
        lateinit var task: FutureTask<Attempt>
    }

    fun connect(handshake: ClientHandshake, io: SessionIo): RoutedTransport = io.operation("route-setup", setupTimeoutMillis.toInt()) {
        val routes = plan(handshake).take(4)
        val completed = ArrayBlockingQueue<FutureTask<Attempt>>(4)
        val attempts = mutableListOf<Attempt>()
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(setupTimeoutMillis)
        var next = 0; var running = 0; var nextLaunch = 0L
        var selected: Attempt? = null
        var setupTimedOut = false
        fun reportFailure(attempt: Attempt) {
            if (attempt.failureReported) return
            attempt.failureReported = true
            fail(attempt.route)
            try { onAttemptFailure(attempt.route, attempt.io.failureStage) } catch (_: Exception) {}
        }
        var last: Exception = java.net.ConnectException()
        try {
            while (true) {
                if (io.closed) { setupTimedOut = io.timedOut; throw java.io.EOFException() }
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) { setupTimedOut = true; throw java.net.SocketTimeoutException() }
                if (next < routes.size && (running == 0 || System.nanoTime() >= nextLaunch)) {
                    val attempt = Attempt(routes[next++], io.child())
                    attempt.task = object : FutureTask<Attempt>(Callable {
                        try {
                            attempt.started = true
                            val connected = connectRoute(attempt.route, attempt.io)
                            attempt.transport.set(connected)
                            if (io.closed || attempt.io.closed) { connected.close(); throw java.io.EOFException() }
                            attempt
                        } catch (failure: Exception) { attempt.io.close(); throw failure }
                    }) { override fun done() { completed.offer(this) } }
                    attempts += attempt
                    try { executor.execute(attempt.task); running++ }
                    catch (failure: java.util.concurrent.RejectedExecutionException) { attempt.io.close(); last = failure }
                    nextLaunch = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(hedgeMillis)
                }
                if (running == 0 && next == routes.size) throw last
                val untilHedge = if (next < routes.size) (nextLaunch - System.nanoTime()).coerceAtLeast(1) else remaining
                val task = completed.poll(minOf(remaining, untilHedge, TimeUnit.MILLISECONDS.toNanos(50)), TimeUnit.NANOSECONDS) ?: continue
                running--
                try {
                    val result = task.get()
                    if (io.closed || result.io.closed) throw java.io.EOFException()
                    result.io.activateTransfer(); selected = result
                    return@operation RoutedTransport(result.transport.get()!!, result.route, this)
                } catch (failure: java.util.concurrent.ExecutionException) {
                    last = failure.cause as? Exception ?: java.io.IOException()
                    attempts.firstOrNull { it.task === task }?.let {
                        if (!io.closed) reportFailure(it)
                    }
                }
            }
            @Suppress("UNREACHABLE_CODE") throw java.io.EOFException()
        } finally {
            // A whole-setup timeout is a real failure for started, unanswered dials.
            // Queue wait and canceled race losers say nothing about endpoint health.
            // Without this distinction blackholed endpoints bypassed the cooldown on
            // every new Telegram connection as soon as the shared deadline expired.
            if (selected == null && (setupTimedOut || io.timedOut)) {
                attempts.filter { it.started && it.transport.get() == null }.forEach(::reportFailure)
            }
            attempts.filter { it !== selected }.forEach {
                it.io.close(); try { it.transport.get()?.close() } catch (_: Exception) {}; it.task.cancel(true)
            }
            executor.purge()
        }
    }

    @Synchronized fun confirm(route: DirectRoute) {
        preferred[route.dc to route.media] = route; failedUntil.remove(route)
    }
    @Synchronized fun fail(route: DirectRoute) {
        failedUntil[route] = now() + TimeUnit.SECONDS.toNanos(30)
        if (preferred[route.dc to route.media] == route) preferred.remove(route.dc to route.media)
    }
    @Synchronized fun plan(handshake: ClientHandshake): List<DirectRoute> {
        // Repeat admission at this boundary: no caller may construct arbitrary DC hostnames.
        val domain = TelegramRelayPolicy.officialDomain(handshake.dc, handshake.media)
        // Media keeps a numeric path too: native DNS may be unavailable while authenticated TCP/TLS works.
        val first = if (handshake.media || handshake.dc !in intArrayOf(2, 4))
            DirectRoute(handshake.dc, handshake.media, domain, domain, DirectStrategy.OFFICIAL_DNS)
        else DirectRoute(handshake.dc, handshake.media, domain, "149.154.167.220", DirectStrategy.FIXED_IP)
        val numericStrategy = if (handshake.media) DirectStrategy.FIXED_IP else DirectStrategy.FRONTED_IP
        val candidates = mutableListOf(first, DirectRoute(handshake.dc, handshake.media, domain, "149.154.167.220", numericStrategy))
        if (useRelays) {
            val offset = relayOffset++ and Int.MAX_VALUE
            // Keep the small catalog available to the breaker, while each session still dials at most four routes.
            repeat(WssRelayCatalog.domains.size) {
                val relay = "kws${handshake.dc}.${WssRelayCatalog.domains[(offset + it) % WssRelayCatalog.domains.size]}"
                candidates += DirectRoute(handshake.dc, handshake.media, relay, relay, DirectStrategy.RELAY_WSS)
            }
        }
        val cached = preferred[handshake.dc to handshake.media]
        if (cached != null) { candidates.remove(cached); candidates.add(0, cached) }
        val current = now()
        failedUntil.entries.removeIf { it.value <= current }
        // An empty healthy set is a failure, not permission to bypass every endpoint's cooldown.
        return candidates.distinct().filter { it !in failedUntil }.take(4)
    }

    override fun close() { executor.shutdownNow() }
}
