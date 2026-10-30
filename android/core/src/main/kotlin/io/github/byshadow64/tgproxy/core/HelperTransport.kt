package io.github.byshadow64.tgproxy.core

import java.io.EOFException
import java.net.Socket
import java.security.MessageDigest
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

internal class HelperTransport private constructor(private val socket: Socket, private val io: SessionIo) : BinaryTransport {
    private val input = socket.getInputStream()
    private val output = socket.getOutputStream()
    private val sendLock = Any()
    private var remaining = 0

    override fun send(bytes: ByteArray) = synchronized(sendLock) {
        if (bytes.size > MAX_FRAME_BYTES) throw ProtocolException()
        io.operation("helper-write", WRITE_TIMEOUT_MS) {
            output.write(byteArrayOf((bytes.size ushr 24).toByte(), (bytes.size ushr 16).toByte(), (bytes.size ushr 8).toByte(), bytes.size.toByte()))
            output.write(bytes); output.flush()
        }
    }

    override fun receive(): ByteArray? = try {
        if (remaining == 0) {
            val first = input.read() // No traffic is not a failed helper session.
            if (first < 0) throw EOFException()
            remaining = io.operation("helper-frame", READ_TIMEOUT_MS) {
                val rest = input.exactly(3)
                val length = (first.toLong() shl 24) or ((rest[0].toLong() and 255) shl 16) or ((rest[1].toLong() and 255) shl 8) or (rest[2].toLong() and 255)
                if (length > MAX_FRAME_BYTES) throw ProtocolException()
                length.toInt()
            }
        }
        io.operation("helper-frame", READ_TIMEOUT_MS) {
            val count = minOf(remaining, STREAM_CHUNK_BYTES)
            input.readChunk(count).also { remaining -= it.size }
        }
    } catch (_: EOFException) { null }

    override fun close() { io.close(); try { socket.close() } catch (_: Exception) {} }

    companion object {
        fun fingerprint(hex: String): ByteArray {
            val value = hex.replace(":", "").replace(" ", "").lowercase()
            require(value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' })
            return ByteArray(32) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        }

        fun connect(settings: HelperSettings, domain: String, io: SessionIo): HelperTransport {
            TelegramRelayPolicy.requireHelperDomain(domain)
            val expected = fingerprint(settings.fingerprintHex)
            val manager = PinnedTrustManager(expected)
            val context = SSLContext.getInstance("TLS").apply { init(null, arrayOf(manager), null) }
            val socket: SSLSocket
            try { socket = tlsConnect(settings.host, settings.port, io, null, context.socketFactory) }
            catch (failure: Exception) {
                if (manager.mismatch.get()) throw PinMismatchException()
                throw failure
            }
            // A second explicit check makes the authentication-before-credentials invariant visible.
            val actual = MessageDigest.getInstance("SHA-256").digest(socket.session.peerCertificates[0].encoded)
            if (!MessageDigest.isEqual(expected, actual)) { socket.close(); throw PinMismatchException() }
            val transport = HelperTransport(socket, io)
            try {
                transport.send(settings.token.toByteArray(Charsets.UTF_8))
                transport.send(domain.toByteArray(Charsets.US_ASCII))
                val response = io.operation("helper-auth", HANDSHAKE_TIMEOUT_MS, socket) {
                    socket.soTimeout = HANDSHAKE_TIMEOUT_MS
                    try { transport.input.exactly(readLength(transport.input, 32)) }
                    finally { socket.soTimeout = 0 }
                }
                if (!response.contentEquals(byteArrayOf(79, 75))) throw HelperRejectedException()
                return transport
            } catch (failure: Exception) { transport.close(); throw failure }
        }
    }
}
