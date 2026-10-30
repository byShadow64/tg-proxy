package io.github.byshadow64.tgproxy.core

import java.io.BufferedInputStream
import java.io.EOFException
import java.io.InputStream
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory

/** MTProto WSS is a byte stream across messages, so receive streams even a large frame in 64 KiB pieces. */
internal class WebSocketTransport private constructor(
    private val socket: Socket, private val input: InputStream, private val io: SessionIo,
) : BinaryTransport {
    private val output = socket.getOutputStream()
    private val sendLock = Any()
    private val lastActivity = AtomicLong(System.nanoTime())
    private val lastPing = AtomicLong(System.nanoTime())
    private var fragmented = false
    private var messageBytes = 0L
    private var remaining = 0
    @Volatile private var closed = false

    override fun send(bytes: ByteArray) {
        if (bytes.size > MAX_FRAME_BYTES) throw ProtocolException()
        writeFrame(2, bytes)
    }
    override fun claimKeepAlive(nowNanos: Long): Boolean {
        val interval = TimeUnit.SECONDS.toNanos(30)
        val previous = lastPing.get()
        return !closed && nowNanos - lastActivity.get() >= interval && nowNanos - previous >= interval && lastPing.compareAndSet(previous, nowNanos)
    }
    override fun keepAlive() { if (!closed) writeFrame(9, ByteArray(0)) }

    private fun writeFrame(opcode: Int, bytes: ByteArray) = synchronized(sendLock) {
        if (closed) throw EOFException()
        val mask = ByteArray(4).also(random::nextBytes)
        val header = java.io.ByteArrayOutputStream(14)
        header.write(0x80 or opcode)
        when {
            bytes.size < 126 -> header.write(0x80 or bytes.size)
            bytes.size < 65536 -> { header.write(0xfe); header.write(bytes.size ushr 8); header.write(bytes.size) }
            else -> { header.write(0xff); repeat(4) { header.write(0) }; for (shift in 24 downTo 0 step 8) header.write(bytes.size ushr shift) }
        }
        header.write(mask)
        io.operation("ws-write", WRITE_TIMEOUT_MS) {
            output.write(header.toByteArray())
            var offset = 0
            while (offset < bytes.size) {
                val count = minOf(STREAM_CHUNK_BYTES, bytes.size - offset)
                val masked = ByteArray(count) { (bytes[offset + it].toInt() xor mask[(offset + it) and 3].toInt()).toByte() }
                output.write(masked); offset += count
            }
            output.flush()
            lastActivity.set(System.nanoTime())
        }
    }

    override fun receive(): ByteArray? = try {
        var result: ByteArray? = null
        while (!closed) {
            if (remaining > 0) {
                result = io.operation("ws-frame", READ_TIMEOUT_MS) {
                    val count = minOf(STREAM_CHUNK_BYTES, remaining)
                    input.readChunk(count).also { remaining -= it.size; lastActivity.set(System.nanoTime()) }
                }
                break
            }
            // A missing next frame is ordinary idle time, not a broken transport.
            val first = input.read()
            if (first < 0) throw EOFException()
            lastActivity.set(System.nanoTime())
            var dataFrame = false
            io.operation("ws-frame", READ_TIMEOUT_MS) {
                val second = input.exactly(1)[0].toInt() and 255
                val fin = first and 0x80 != 0
                val opcode = first and 15
                if (first and 0x70 != 0 || second and 0x80 != 0 || opcode !in intArrayOf(0, 2, 8, 9, 10)) throw ProtocolException()
                var size = (second and 127).toLong()
                if (opcode >= 8 && (!fin || size > 125)) throw ProtocolException()
                if (size == 126L) {
                    val extended = input.exactly(2)
                    size = ((extended[0].toInt() and 255) shl 8 or (extended[1].toInt() and 255)).toLong()
                    if (size < 126) throw ProtocolException()
                } else if (size == 127L) {
                    val extended = input.exactly(8)
                    if (extended[0].toInt() and 0x80 != 0) throw ProtocolException()
                    size = extended.fold(0L) { acc, byte -> (acc shl 8) or (byte.toLong() and 255) }
                    if (size < 65536) throw ProtocolException()
                }
                if (size > MAX_FRAME_BYTES) throw ProtocolException()
                if (opcode >= 8) {
                    val payload = input.exactly(size.toInt())
                    when (opcode) {
                        8 -> {
                            validateClose(payload)
                            try { writeFrame(8, payload.take(2).toByteArray()) } catch (_: Exception) {}
                            close()
                        }
                        9 -> writeFrame(10, payload)
                    }
                } else {
                    if (opcode == 0) {
                        if (!fragmented) throw ProtocolException()
                        messageBytes += size
                    } else {
                        if (fragmented) throw ProtocolException()
                        messageBytes = size
                    }
                    if (messageBytes > MAX_FRAME_BYTES) throw ProtocolException()
                    fragmented = !fin
                    remaining = size.toInt()
                    if (remaining > 0) {
                        val count = minOf(STREAM_CHUNK_BYTES, remaining)
                        result = input.readChunk(count).also { remaining -= it.size; lastActivity.set(System.nanoTime()) }
                        dataFrame = true
                    } else if (fin) { result = ByteArray(0); dataFrame = true }
                }
            }
            if (dataFrame) break
        }
        result
    } catch (_: EOFException) { close(); null }

    override fun close() { closed = true; io.abort(socket) }

    companion object {
        private val random = SecureRandom()
        private const val GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

        fun connect(host: String, domain: String, io: SessionIo, port: Int = 443, factory: SSLSocketFactory = SSLContext.getDefault().socketFactory, sni: String? = null, timeoutMs: Int = 8_000): WebSocketTransport {
            val socket = tlsConnect(host, port, io, domain, factory, sni, timeoutMs)
            return upgrade(socket, domain, io, timeoutMs)
        }

        /** Internal seam permits loopback protocol fixtures without weakening production TLS. */
        internal fun upgrade(socket: Socket, domain: String, io: SessionIo, timeoutMs: Int = HANDSHAKE_TIMEOUT_MS): WebSocketTransport {
            val input = BufferedInputStream(socket.getInputStream(), STREAM_CHUNK_BYTES)
            try {
                io.operation("ws-upgrade", timeoutMs, socket) {
                    socket.soTimeout = timeoutMs
                    val key = Base64.getEncoder().encodeToString(ByteArray(16).also(random::nextBytes))
                    val request = "GET /apiws HTTP/1.1\r\nHost: $domain\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: $key\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n\r\n"
                    socket.getOutputStream().apply { write(request.toByteArray(Charsets.US_ASCII)); flush() }
                    val response = java.io.ByteArrayOutputStream()
                    var matched = 0
                    val delimiter = byteArrayOf(13, 10, 13, 10)
                    while (matched < 4) {
                        val byte = input.read()
                        if (byte < 0) throw EOFException()
                        if (byte > 127 || (byte < 32 && byte != 13 && byte != 10 && byte != 9)) throw ProtocolException()
                        response.write(byte)
                        if (response.size() > 32 * 1024) throw ProtocolException()
                        matched = if (byte == delimiter[matched].toInt()) matched + 1 else if (byte == 13) 1 else 0
                    }
                    validateUpgrade(response.toString("US-ASCII"), key)
                    socket.soTimeout = 0
                }
                return WebSocketTransport(socket, input, io)
            } catch (failure: Exception) { io.abort(socket); throw failure }
        }

        internal fun validateUpgrade(response: String, key: String) {
            val lines = response.split("\r\n")
            if (!lines.first().matches(Regex("HTTP/1\\.1 101(?: .*)?"))) throw ProtocolException()
            val headers = mutableMapOf<String, String>()
            for (line in lines.drop(1)) {
                if (line.isEmpty()) continue
                val colon = line.indexOf(':')
                if (colon <= 0 || line.first().isWhitespace()) throw ProtocolException()
                val name = line.substring(0, colon).lowercase()
                if (!name.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }) throw ProtocolException()
                val value = line.substring(colon + 1).trim()
                headers[name] = headers[name]?.let { "$it,$value" } ?: value
            }
            val expected = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((key + GUID).toByteArray(Charsets.US_ASCII)))
            if (!headers["upgrade"].equals("websocket", true) ||
                headers["connection"]?.split(',')?.none { it.trim().equals("upgrade", true) } != false ||
                !MessageDigest.isEqual((headers["sec-websocket-accept"] ?: "").toByteArray(), expected.toByteArray()) ||
                headers["sec-websocket-protocol"] != "binary" || headers.containsKey("sec-websocket-extensions")) throw ProtocolException()
        }

        private fun validateClose(bytes: ByteArray) {
            if (bytes.size == 1) throw ProtocolException()
            if (bytes.size >= 2) {
                val code = (bytes[0].toInt() and 255) shl 8 or (bytes[1].toInt() and 255)
                if (!((code in 1000..1014 && code !in intArrayOf(1004, 1005, 1006)) || code in 3000..4999)) throw ProtocolException()
                try { Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes, 2, bytes.size - 2)) }
                catch (_: Exception) { throw ProtocolException() }
            }
        }
    }
}
