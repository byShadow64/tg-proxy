package io.github.byshadow64.tgproxy.core

import java.io.EOFException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.Semaphore
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import java.util.ArrayDeque

/** Real local MTProto proxy. Call start/stop from a worker thread; stop is bounded. */
class ProxyEngine(private val config: EngineConfig, private val listener: (EngineEvent) -> Unit = {}) : AutoCloseable {
    private var helperConnectionProvider: HelperConnectionProvider? = null
    constructor(config: EngineConfig, helperConnectionProvider: HelperConnectionProvider, listener: (EngineEvent) -> Unit = {}) : this(config, listener) {
        this.helperConnectionProvider = helperConnectionProvider
    }
    private var connectorOverride: ((ClientHandshake, SessionIo) -> BinaryTransport)? = null
    internal constructor(config: EngineConfig, connector: (ClientHandshake, SessionIo) -> BinaryTransport, listener: (EngineEvent) -> Unit = {}) : this(config, listener) {
        connectorOverride = connector
    }
    private val lock = Any()
    @Volatile private var run: Run? = null
    private val active = AtomicInteger()
    private val total = AtomicLong()
    private val up = AtomicLong()
    private val down = AtomicLong()
    private val direct = AtomicLong()
    private val helper = AtomicLong()
    private val relays = AtomicLong()

    fun start() {
        val secret = try {
            require(config.port in 1..65535 && config.maxConnections in 1..64)
            config.helper?.let {
                require(it.port in 1..65535 && it.host.length in 1..253 && it.host.all { c -> c.isLetterOrDigit() || c in ".:-" })
                val size = it.token.toByteArray(Charsets.UTF_8).size
                require(size <= 512 && (helperConnectionProvider != null || size >= 32))
                HelperTransport.fingerprint(it.fingerprintHex)
            }
            Obfuscated2.secret(config.secretHex)
        } catch (_: Exception) { throw EngineException(EngineFailureCode.INVALID_CONFIGURATION) }
        synchronized(lock) {
            if (run != null) throw EngineException(EngineFailureCode.ALREADY_RUNNING)
            val server = ServerSocket()
            try {
                // Linux/Android require both old and new listeners to opt in for immediate TIME_WAIT reuse.
                // SO_REUSEPORT is never enabled: an already active listener still owns this loopback port.
                server.reuseAddress = true
                server.bind(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), config.port), config.maxConnections)
            } catch (_: Exception) {
                try { server.close() } catch (_: Exception) {}
                throw EngineException(EngineFailureCode.PORT_UNAVAILABLE)
            }
            val next = Run(server, secret)
            run = next
            next.start()
        }
        emit(EventCode.STARTED)
    }

    fun stop() {
        val previous = synchronized(lock) { run.also { run = null } } ?: return
        previous.close()
        emit(EventCode.STOPPED)
    }

    override fun close() = stop()

    fun snapshot() = EngineStats(
        state = if (run == null) EngineState.STOPPED else EngineState.RUNNING,
        port = if (run == null) 0 else config.port,
        activeConnections = active.get(), totalConnections = total.get(), bytesUp = up.get(), bytesDown = down.get(),
        directConnections = direct.get(), helperConnections = helper.get(),
        relayConnections = relays.get(),
    )

    private fun emit(code: EventCode, handshake: ClientHandshake? = null, route: RouteKind? = null, stage: EngineStage? = null, selected: DirectRoute? = null, handshakeFailure: HandshakeFailure? = null) {
        val strategy = selected?.let { RouteStrategy.valueOf(it.strategy.name) }
        val relayIndex = selected?.takeIf { it.strategy == DirectStrategy.RELAY_WSS }?.let { selectedRoute ->
            WssRelayCatalog.domains.indexOfFirst { selectedRoute.domain == "kws${selectedRoute.dc}.$it" }.takeIf { it >= 0 }
        }
        try { listener(EngineEvent(code, active.get(), handshake?.dc ?: selected?.dc, handshake?.media ?: selected?.media ?: false, route, stage, strategy, relayIndex, handshakeFailure)) } catch (_: Exception) {}
    }

    private inner class Run(val server: ServerSocket, val secret: ByteArray) : AutoCloseable {
        val slots = Semaphore(config.maxConnections)
        val directRoutes = DirectRoutePlanner(onAttemptFailure = { failed, stage ->
            emit(EventCode.ROUTE_ATTEMPT_FAILED, stage = stage, selected = failed)
        })
        val sessions = ConcurrentHashMap.newKeySet<SessionIo>()
        val transports = ConcurrentHashMap<SessionIo, BinaryTransport>()
        val workers = boundedExecutor(config.maxConnections, "session")
        val uplinks = boundedExecutor(config.maxConnections, "uplink")
        val watchdog: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor(daemonFactory("deadline"))
        val keepAlives = java.util.concurrent.ThreadPoolExecutor(2, 2, 30, TimeUnit.SECONDS, ArrayBlockingQueue(64), daemonFactory("keepalive"), ThreadPoolExecutor.AbortPolicy()).apply { allowCoreThreadTimeOut(true) }
        val acceptor = Thread({ accept() }, "tgproxy-listener").apply { isDaemon = true }
        @Volatile var closing = false

        fun start() {
            watchdog.scheduleAtFixedRate({
                val now = System.nanoTime(); sessions.forEach { it.expire(now) }
                transports.forEach { (io, transport) ->
                    if (!io.closed && transport.claimKeepAlive(now)) try {
                        keepAlives.execute { try { if (!io.closed) transport.keepAlive() } catch (_: Exception) { io.close() } }
                    } catch (_: RejectedExecutionException) { /* Bounded best-effort keepalive; never block the deadline watchdog. */ }
                }
            }, 100, 100, TimeUnit.MILLISECONDS)
            acceptor.start()
        }

        private fun accept() {
            while (!closing) {
                val client = try { server.accept() } catch (_: Exception) { break }
                total.incrementAndGet()
                if (closing || !slots.tryAcquire()) {
                    try { client.close() } catch (_: Exception) {}
                    if (!closing) emit(EventCode.CONNECTION_LIMIT)
                    continue
                }
                val io = SessionIo()
                io.track(client)
                synchronized(this) {
                    if (closing) { io.close(); slots.release(); return }
                    sessions.add(io); active.incrementAndGet()
                }
                emit(EventCode.CONNECTION_OPENED)
                try { workers.execute { session(client, io) } }
                catch (_: RejectedExecutionException) {
                    if (!closing) emit(EventCode.CONNECTION_LIMIT)
                    finish(io)
                }
            }
        }

        private fun finish(io: SessionIo) {
            io.close()
            transports.remove(io)
            if (sessions.remove(io)) {
                active.decrementAndGet(); slots.release()
                if (io.timedOut && !closing) emit(EventCode.TIMEOUT, stage = io.failureStage)
                emit(EventCode.CONNECTION_CLOSED)
            }
        }

        private fun session(client: Socket, io: SessionIo) {
            var transport: BinaryTransport? = null
            val replyGate = Any()
            var firstReplySeen = false
            var firstReplyArmed = false
            var relayWritten = false
            var upstreamClosedBeforeReply = false
            fun sentClientPacket() = synchronized(replyGate) {
                if (!firstReplySeen && !firstReplyArmed) { io.expectFirstReply(); firstReplyArmed = true }
            }
            try {
                client.tcpNoDelay = true; client.soTimeout = HANDSHAKE_TIMEOUT_MS
                val input = client.getInputStream(); val output = client.getOutputStream()
                val init = io.operation("client-init", HANDSHAKE_TIMEOUT_MS) { input.exactly(64) }
                val inspected = Obfuscated2.inspect(init, secret)
                val handshake = inspected.handshake
                if (handshake == null) { emit(EventCode.INVALID_HANDSHAKE, stage = EngineStage.CLIENT_HANDSHAKE, handshakeFailure = inspected.failure); return }
                if (!TelegramRelayPolicy.supportsDc(handshake.dc)) { emit(EventCode.UNSUPPORTED_DC); return }
                client.soTimeout = 0 // A quiet direction is normal while Telegram transfers on the other one.
                val relay = Obfuscated2.relayInit(handshake)
                val crypto = Obfuscated2.context(handshake, secret, relay)
                val upstream = AtomicReference<BinaryTransport?>()
                // Watch client EOF while dialing instead of holding abandoned Telegram attempts until setup ends.
                // Only two encrypted read chunks are retained; no transport/crypto bytes are consumed twice.
                client.soTimeout = 100
                uplinks.execute {
                    val splitter = MsgSplitter(handshake.protocol)
                    val pending = ArrayDeque<ByteArray>()
                    try {
                        val buffer = ByteArray(STREAM_CHUNK_BYTES)
                        var destination: BinaryTransport? = null
                        fun forward(chunk: ByteArray, writer: BinaryTransport) {
                            val plain = crypto.clientDecrypt.update(chunk)
                            val before = splitter.completedPackets
                            splitter.split(crypto.telegramEncrypt.update(plain), plain).forEach(writer::send)
                            if (splitter.completedPackets > before) sentClientPacket()
                            up.addAndGet(chunk.size.toLong())
                        }
                        while (!io.closed) {
                            if (destination == null) {
                                destination = upstream.get()
                                if (destination != null) {
                                    client.soTimeout = 0
                                    while (pending.isNotEmpty()) forward(pending.removeFirst(), destination)
                                } else if (pending.size >= 2) { Thread.sleep(10); continue }
                            }
                            val count = try { input.read(buffer) }
                            catch (_: SocketTimeoutException) { continue }
                            catch (_: java.net.SocketException) { break }
                            if (count < 0) { destination?.let { splitter.flush().forEach(it::send) }; break }
                            if (count == 0) continue
                            val chunk = buffer.copyOf(count)
                            if (destination == null) pending.addLast(chunk) else forward(chunk, destination)
                        }
                    } catch (failure: Exception) { reportFailure(failure, io) }
                    finally { pending.clear(); splitter.close(); io.close() }
                }
                val connected = if (config.helper != null) io.operation("helper-setup", 8_000) {
                    val configured = config.helper
                    val leased = helperConnectionProvider?.settings { io.closed || Thread.currentThread().isInterrupted } ?: configured
                    // A signed renewal may rotate port/pin; it cannot redirect the user's configured server IP.
                    if (leased.host != configured.host || leased.port !in 1..65535 || leased.token.toByteArray(Charsets.UTF_8).size !in 32..512) throw HelperRejectedException()
                    HelperTransport.connect(leased, domains(handshake).first(), io)
                }
                    else connectorOverride?.invoke(handshake, io) ?: directRoutes.connect(handshake, io)
                transport = connected
                val route = synchronized(this) {
                    // Serialize acceptance and its event with Stop. A late connector cannot
                    // publish a route after its session was retired. Network I/O stays outside.
                    if (io.closed || closing) throw EOFException()
                    transports[io] = connected
                    io.clearSetupFailure()
                    val selectedRoute = when {
                        config.helper != null -> RouteKind.HELPER_TLS
                        (connected as? RoutedTransport)?.route?.strategy == DirectStrategy.RELAY_WSS -> RouteKind.RELAY_WSS
                        else -> RouteKind.DIRECT_WSS
                    }
                    when (selectedRoute) { RouteKind.DIRECT_WSS -> direct.incrementAndGet(); RouteKind.RELAY_WSS -> relays.incrementAndGet(); RouteKind.HELPER_TLS -> helper.incrementAndGet() }
                    emit(EventCode.ROUTE_CONNECTED, handshake, selectedRoute, selected = (connected as? RoutedTransport)?.route)
                    selectedRoute
                }
                connected.send(relay)
                relayWritten = true
                upstream.set(connected)
                while (!io.closed) {
                    val data = connected.receive()
                    if (data == null) {
                        if (!io.closed) {
                            upstreamClosedBeforeReply = true
                            if (synchronized(replyGate) { !firstReplySeen }) emit(
                                EventCode.UPSTREAM_UNAVAILABLE, handshake, route, EngineStage.FIRST_REPLY,
                                selected = (connected as? RoutedTransport)?.route,
                            )
                        }
                        break
                    }
                    if (data.isNotEmpty()) synchronized(replyGate) {
                        if (!firstReplySeen) {
                            firstReplySeen = true; io.receivedFirstReply()
                            (connected as? RoutedTransport)?.confirmedResponse()
                        }
                    }
                    val encrypted = crypto.clientEncrypt.update(crypto.telegramDecrypt.update(data))
                    io.operation("client-write", WRITE_TIMEOUT_MS) { output.write(encrypted); output.flush() }
                    down.addAndGet(data.size.toLong())
                }
            } catch (failure: Exception) { reportFailure(failure, io) }
            finally {
                synchronized(replyGate) {
                    if (!firstReplySeen && (firstReplyArmed || upstreamClosedBeforeReply || (!relayWritten && !io.closed)))
                        (transport as? RoutedTransport)?.failedFirstReply()
                }
                try { transport?.close() } catch (_: Exception) {}; finish(io)
            }
        }

        private fun reportFailure(failure: Exception, io: SessionIo) {
            if (closing || io.closed) return
            val code = when (failure) {
                is PinMismatchException -> EventCode.HELPER_PIN_MISMATCH
                is HelperRejectedException -> EventCode.HELPER_REJECTED
                is ProtocolException -> EventCode.PROTOCOL_ERROR
                is SocketTimeoutException -> EventCode.TIMEOUT
                is RejectedExecutionException -> EventCode.CONNECTION_LIMIT
                is EOFException -> return
                else -> EventCode.UPSTREAM_UNAVAILABLE
            }
            emit(code, stage = io.failureStage)
        }

        override fun close() {
            val joinDeadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(500)
            synchronized(this) { closing = true }
            try { server.close() } catch (_: Exception) {}
            sessions.forEach { it.close() }
            directRoutes.close()
            workers.shutdownNow(); uplinks.shutdownNow(); watchdog.shutdownNow(); keepAlives.shutdownNow()
            // Service destruction can call stop on Android's main thread. Close owned sockets
            // immediately, then share one short join budget instead of accumulating five waits.
            // Native DNS or third-party I/O can ignore interruption; their late results are
            // discarded by the closed SessionIo, not reported as terminated threads here.
            try {
                val remaining = joinDeadline - System.nanoTime()
                if (remaining > 0) TimeUnit.NANOSECONDS.timedJoin(acceptor, remaining)
            } catch (_: InterruptedException) { Thread.currentThread().interrupt() }
            for (executor in listOf(workers, uplinks, watchdog, keepAlives)) {
                val remaining = joinDeadline - System.nanoTime()
                if (remaining <= 0) break
                try { executor.awaitTermination(remaining, TimeUnit.NANOSECONDS) } catch (_: InterruptedException) { Thread.currentThread().interrupt() }
            }
            sessions.toList().forEach { finish(it) }
            secret.fill(0)
        }
    }

    companion object {
        private fun domains(handshake: ClientHandshake): List<String> {
            val primary = TelegramRelayPolicy.officialDomain(handshake.dc, handshake.media)
            return if (handshake.media) listOf(primary, TelegramRelayPolicy.officialDomain(handshake.dc, false)) else listOf(primary)
        }
        private fun daemonFactory(kind: String) = ThreadFactory { task -> Thread(task, "tgproxy-$kind").apply { isDaemon = true } }
        internal fun boundedExecutor(limit: Int, kind: String): ThreadPoolExecutor = ThreadPoolExecutor(
            limit, limit, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue(limit), daemonFactory(kind),
            ThreadPoolExecutor.AbortPolicy(),
        )
    }
}
