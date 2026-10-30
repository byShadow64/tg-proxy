package io.github.byshadow64.tgproxy.core

import java.io.EOFException
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Callable
import java.util.concurrent.FutureTask
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

internal fun dnsExecutor() = ThreadPoolExecutor(2, 2, 30, TimeUnit.SECONDS, ArrayBlockingQueue(16), { task ->
    Thread(task, "tgproxy-dns").apply { isDaemon = true }
}).apply { allowCoreThreadTimeOut(true) }

/** Native DNS may ignore interruption. Abandoned running calls remain shared until actual completion. */
internal class SharedHostResolver(
    private val lookupAddresses: (String) -> List<InetAddress> = { BoundedDns.preferIpv4(InetAddress.getAllByName(it).toList()) },
    private val executor: ThreadPoolExecutor = dnsExecutor(),
) : AutoCloseable {
    private data class Cached(val addresses: List<InetAddress>, val until: Long)
    private val lock = Any()
    private val inFlight = mutableMapOf<String, Lookup>()
    private val cache = object : LinkedHashMap<String, Cached>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Cached>?) = size > 64
    }
    @Volatile private var closed = false
    private inner class Lookup(val host: String) {
        val started = AtomicBoolean()
        var waiters = 0
        val task: FutureTask<List<InetAddress>> = object : FutureTask<List<InetAddress>>(Callable { lookupAddresses(host) }) {
            override fun run() { started.set(true); super.run() }
            override fun done() {
                synchronized(lock) {
                    if (!isCancelled && !closed) try {
                        val addresses = get()
                        if (addresses.isNotEmpty()) cache[host] = Cached(addresses, System.nanoTime() + TimeUnit.SECONDS.toNanos(60))
                    } catch (_: Exception) {}
                    inFlight.remove(host, this@Lookup)
                }
            }
        }
    }

    fun resolveAll(host: String, io: SessionIo, timeoutMs: Int = 5_000): List<InetAddress> = io.operation("dns", timeoutMs.coerceIn(1, 5_000)) {
        val lookup = synchronized(lock) {
            if (closed || io.closed) throw EOFException()
            cache[host]?.takeIf { it.until > System.nanoTime() }?.let { return@operation it.addresses }
            val shared = inFlight[host] ?: Lookup(host).also {
                executor.execute(it.task)
                inFlight[host] = it
            }
            shared.waiters++; shared
        }
        try {
            val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs.coerceIn(1, 5_000).toLong())
            while (true) {
                if (io.closed) throw EOFException()
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) throw SocketTimeoutException()
                try {
                    return@operation lookup.task.get(minOf(remaining, TimeUnit.MILLISECONDS.toNanos(50)), TimeUnit.NANOSECONDS)
                } catch (_: java.util.concurrent.TimeoutException) {
                    if (System.nanoTime() >= deadline) throw SocketTimeoutException()
                }
            }
            @Suppress("UNREACHABLE_CODE") throw EOFException()
        } finally {
            synchronized(lock) {
                lookup.waiters--
                // Removing a queued task proves native DNS has not started. A running call cannot be canceled safely.
                if (lookup.waiters == 0 && !lookup.started.get() && executor.remove(lookup.task)) lookup.task.cancel(false)
            }
        }
    }

    override fun close() {
        synchronized(lock) {
            closed = true
            executor.shutdownNow().forEach { (it as? FutureTask<*>)?.cancel(false) }
            cache.clear()
        }
    }
}
