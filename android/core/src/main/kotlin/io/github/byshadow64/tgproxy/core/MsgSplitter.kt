package io.github.byshadow64.tgproxy.core

import java.util.ArrayDeque

/** Counts retained plaintext+ciphertext; complete emitted packets are no longer retained here. */
internal class SplitterBudget(val limit: Long = 16L * 1024 * 1024) {
    @Volatile var used: Long = 0; private set
    init { require(limit >= 0) }
    @Synchronized fun reserve(size: Long): Boolean {
        require(size >= 0)
        if (size > limit - used) return false
        used += size
        return true
    }
    @Synchronized fun release(size: Long) { check(size in 0..used); used -= size }
}

/** Desktop-compatible client packet coalescing, with a smaller shared mobile buffer budget. */
internal class MsgSplitter(private val protocol: TransportProtocol, private val budget: SplitterBudget = sharedBudget) : AutoCloseable {
    private class Segment(val cipher: ByteArray, val plain: ByteArray, var offset: Int = 0)
    private val segments = ArrayDeque<Segment>()
    private var buffered = 0
    private var reserved = 0L
    var disabled = false; private set
    var completedPackets = 0L; private set

    fun split(cipher: ByteArray, plain: ByteArray): List<ByteArray> {
        if (cipher.size != plain.size) { close(); throw IllegalArgumentException("Cipher/plain length mismatch") }
        if (cipher.isEmpty()) return emptyList()
        if (disabled) return streamParts(cipher)
        if (cipher.size > MAX_COALESCED_PACKET || !budget.reserve(cipher.size.toLong() * 2)) {
            val pending = drainStreaming()
            disabled = true
            return pending + streamParts(cipher)
        }
        reserved += cipher.size.toLong() * 2
        segments.addLast(Segment(cipher, plain)); buffered += cipher.size
        try {
            val output = mutableListOf<ByteArray>()
            while (buffered > 0) {
                val length = nextPacketLength() ?: break
                if (length <= 0) { output += drainStreaming(); disabled = true; break }
                output += take(length)
                completedPackets++
            }
            compactHead()
            return output
        } catch (failure: Throwable) { close(); throw failure }
    }

    fun flush(): List<ByteArray> = if (buffered == 0) emptyList() else listOf(take(buffered))

    private fun nextPacketLength(): Int? {
        val header: Int
        val payload: Long
        if (protocol == TransportProtocol.ABRIDGED) {
            val first = peek(0)
            if (first == 0x7f || first == 0xff) {
                if (buffered < 4) return null
                header = 4
                payload = ((peek(1).toLong()) or (peek(2).toLong() shl 8) or (peek(3).toLong() shl 16)) * 4
            } else { header = 1; payload = (first and 0x7f).toLong() * 4 }
        } else {
            if (buffered < 4) return null
            header = 4
            payload = (peek(0).toLong() or (peek(1).toLong() shl 8) or (peek(2).toLong() shl 16) or (peek(3).toLong() shl 24)) and 0x7fff_ffffL
        }
        val length = header + payload
        if (payload <= 0 || length > MAX_COALESCED_PACKET) return 0
        return if (buffered < length) null else length.toInt()
    }

    private fun peek(index: Int): Int {
        var remaining = index
        for (segment in segments) {
            val available = segment.plain.size - segment.offset
            if (remaining < available) return segment.plain[segment.offset + remaining].toInt() and 255
            remaining -= available
        }
        throw IllegalStateException()
    }

    private fun take(size: Int): ByteArray {
        val output = ByteArray(size)
        var offset = 0
        while (offset < size) {
            val segment = segments.first
            val count = minOf(size - offset, segment.cipher.size - segment.offset)
            segment.cipher.copyInto(output, offset, segment.offset, segment.offset + count)
            offset += count; segment.offset += count
            if (segment.offset == segment.cipher.size) segments.removeFirst()
        }
        buffered -= size
        val released = size.toLong() * 2
        reserved -= released; budget.release(released)
        return output
    }

    private fun drainStreaming(): List<ByteArray> {
        val result = mutableListOf<ByteArray>()
        while (segments.isNotEmpty()) {
            val segment = segments.removeFirst()
            val bytes = if (segment.offset == 0) segment.cipher else segment.cipher.copyOfRange(segment.offset, segment.cipher.size)
            result += streamParts(bytes)
        }
        buffered = 0
        if (reserved > 0) budget.release(reserved)
        reserved = 0
        return result
    }

    private fun compactHead() {
        val first = segments.peekFirst() ?: return
        if (first.offset == 0) return
        segments.removeFirst()
        segments.addFirst(Segment(first.cipher.copyOfRange(first.offset, first.cipher.size), first.plain.copyOfRange(first.offset, first.plain.size)))
    }

    override fun close() {
        disabled = true; segments.clear(); buffered = 0
        if (reserved > 0) budget.release(reserved)
        reserved = 0
    }

    companion object {
        const val MAX_COALESCED_PACKET = 1024 * 1024 + 19
        internal val sharedBudget = SplitterBudget()
        private fun streamParts(bytes: ByteArray): List<ByteArray> {
            if (bytes.size <= STREAM_CHUNK_BYTES) return listOf(bytes)
            val parts = mutableListOf<ByteArray>()
            var offset = 0
            while (offset < bytes.size) {
                val end = minOf(offset + STREAM_CHUNK_BYTES, bytes.size)
                parts += bytes.copyOfRange(offset, end); offset = end
            }
            return parts
        }
    }
}
