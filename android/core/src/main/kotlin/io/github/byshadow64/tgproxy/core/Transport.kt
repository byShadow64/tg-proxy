package io.github.byshadow64.tgproxy.core

import java.io.Closeable
import java.io.EOFException
import java.io.InputStream
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

internal const val MAX_FRAME_BYTES = 16 * 1024 * 1024
internal const val STREAM_CHUNK_BYTES = 64 * 1024
internal const val CONNECT_TIMEOUT_MS = 10_000
internal const val HANDSHAKE_TIMEOUT_MS = 15_000
internal const val READ_TIMEOUT_MS = 120_000
internal const val WRITE_TIMEOUT_MS = 30_000

internal class ProtocolException : Exception()
internal class PinMismatchException : Exception()
internal class HelperRejectedException : Exception()

internal interface BinaryTransport : Closeable {
    fun send(bytes: ByteArray)
    fun receive(): ByteArray?
    fun claimKeepAlive(nowNanos: Long): Boolean = false
    fun keepAlive() {}
}

/** Each blocking operation has a deadline. The engine watchdog closes sockets on expiry. */
internal class SessionIo(private val parent: SessionIo? = null) : Closeable {
    private class Deadline(val until: Long, val abortSocket: Socket?, val fired: AtomicBoolean = AtomicBoolean())
    private val sockets = ConcurrentHashMap.newKeySet<Socket>()
    private val rawSockets = ConcurrentHashMap<Socket, Socket>()
    private val deadlines = ConcurrentHashMap<String, Deadline>()
    private val children = ConcurrentHashMap.newKeySet<SessionIo>()
    @Volatile private var activeTransfer = false
    @Volatile var closed = false; private set
    @Volatile var timedOut = false; private set
    @Volatile var failureStage: EngineStage? = null; private set
    fun clearSetupFailure() { failureStage = null }
    private fun failure(stage: EngineStage?) { failureStage = stage; parent?.failure(stage) }
    private fun timeout(stage: EngineStage?) { timedOut = true; failure(stage); if (activeTransfer) parent?.timeout(stage) }
    fun activateTransfer() { activeTransfer = true }
    @Synchronized fun child(): SessionIo {
        if (closed) throw EOFException()
        return SessionIo(this).also(children::add)
    }

    fun expectFirstReply() {
        if (!closed) deadlines.putIfAbsent("first-reply", Deadline(System.nanoTime() + TimeUnit.SECONDS.toNanos(20), null))
    }
    fun receivedFirstReply() { deadlines.remove("first-reply") }

    @Synchronized fun track(socket: Socket, raw: Socket? = null): Socket {
        if (closed) { socket.close(); throw EOFException() }
        sockets.add(socket)
        if (raw != null) rawSockets[socket] = raw
        return socket
    }
    fun <T> operation(name: String, timeoutMs: Int, abortSocket: Socket? = null, action: () -> T): T {
        if (closed) throw EOFException()
        val deadline = Deadline(System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs.toLong()), abortSocket)
        deadlines[name] = deadline
        try { return action() }
        catch (failure: Exception) {
            if (!closed) failure(stage(name))
            if (deadline.fired.get()) throw java.net.SocketTimeoutException()
            throw failure
        }
        finally { deadlines.remove(name, deadline) }
    }
    fun expire(now: Long) {
        children.forEach { it.expire(now) }
        val expired = deadlines.entries.filter { now >= it.value.until && !it.value.fired.get() }.minByOrNull { it.value.until }
        if (!closed && expired != null && expired.value.fired.compareAndSet(false, true)) {
            failure(stage(expired.key))
            if (expired.value.abortSocket != null) abort(expired.value.abortSocket!!)
            else { timeout(stage(expired.key)); close() }
        }
    }
    fun abort(socket: Socket) {
        val raw = rawSockets.remove(socket)
        if (raw != null) { try { raw.close() } catch (_: Exception) {}; sockets.remove(raw) }
        try { socket.close() } catch (_: Exception) {}
        sockets.remove(socket)
    }
    @Synchronized override fun close() {
        closed = true
        children.toList().forEach { it.close() }; children.clear()
        // Abort the raw descriptors first: TLS close_notify must never wait behind a blocked TLS write.
        val copy = sockets.toList()
        copy.filterNot { it is javax.net.ssl.SSLSocket }.forEach { try { it.close() } catch (_: Exception) {} }
        copy.filterIsInstance<javax.net.ssl.SSLSocket>().forEach { try { it.close() } catch (_: Exception) {} }
        sockets.clear(); rawSockets.clear(); deadlines.clear()
        parent?.children?.remove(this)
    }

    private fun stage(name: String): EngineStage? = when (name) {
        "client-init" -> EngineStage.CLIENT_HANDSHAKE
        "dns" -> EngineStage.DNS
        "connect" -> EngineStage.CONNECT
        "route-setup" -> EngineStage.CONNECT
        "tls" -> EngineStage.TLS
        "ws-upgrade" -> EngineStage.WEBSOCKET_HANDSHAKE
        "helper-auth" -> EngineStage.HELPER_AUTH
        "helper-setup" -> EngineStage.HELPER_AUTH
        "first-reply" -> EngineStage.FIRST_REPLY
        "ws-frame", "helper-frame" -> EngineStage.FRAME_PROGRESS
        "client-write", "helper-write", "ws-write" -> EngineStage.WRITE
        else -> null
    }
}

internal fun InputStream.exactly(size: Int): ByteArray {
    if (size < 0 || size > MAX_FRAME_BYTES) throw ProtocolException()
    val bytes = ByteArray(size)
    var offset = 0
    while (offset < size) {
        val read = read(bytes, offset, size - offset)
        if (read < 0) throw EOFException()
        if (read == 0) continue
        offset += read
    }
    return bytes
}

/** Binary transports are streams: forward bytes already received without filling a 64 KiB batch. */
internal fun InputStream.readChunk(limit: Int): ByteArray {
    if (limit < 0 || limit > STREAM_CHUNK_BYTES) throw ProtocolException()
    if (limit == 0) return ByteArray(0)
    val bytes = ByteArray(limit)
    while (true) {
        val count = read(bytes)
        if (count < 0) throw EOFException()
        if (count > 0) return if (count == bytes.size) bytes else bytes.copyOf(count)
    }
}

internal fun readLength(input: InputStream, limit: Int = MAX_FRAME_BYTES): Int {
    val bytes = input.exactly(4)
    val value = bytes.fold(0L) { acc, byte -> (acc shl 8) or (byte.toLong() and 255) }
    if (value > limit) throw ProtocolException()
    return value.toInt()
}
