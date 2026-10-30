package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.net.Socket
import java.security.MessageDigest
import java.util.Base64

class WebSocketTransportTest {
    @Test fun rejectsInvalidUpgrades() {
        val key = "fixture-key"
        val valid = upgradeResponse(key)
        WebSocketTransport.validateUpgrade(valid, key)
        for (invalid in listOf(
            valid.replace("HTTP/1.1", "HTTP/1.0"), valid.replace("HTTP/1.1", "BOGUS"),
            valid.replace("101", "200"), valid.replace("binary", "text"),
            valid.replace("Connection: Upgrade", "Connection: keep-alive"),
            valid.replace("Sec-WebSocket-Accept:", "Wrong-Accept:"),
            valid.replace("\r\n\r\n", "\r\nSec-WebSocket-Extensions: compression\r\n\r\n"),
            valid.replace("\r\n\r\n", "\r\nSec-WebSocket-Protocol: binary\r\n\r\n"),
        )) {
            try { WebSocketTransport.validateUpgrade(invalid, key); fail(invalid) } catch (_: ProtocolException) {}
        }
    }

    @Test fun verifiesDirectTlsHostnameBeforeSendingUpgrade() {
        TlsFixture.server { socket ->
            try { socket.getInputStream().read() } catch (_: Exception) {}
        }.use { server ->
            SessionIo().use { io ->
                try { WebSocketTransport.connect("127.0.0.1", "wrong.invalid", io, server.port, TlsFixture.clientFactory); fail() }
                catch (_: javax.net.ssl.SSLHandshakeException) {}
            }
            server.assertSuccess()
        }
    }

    @Test fun directTlsUpgradeAndMaskedClientFramesWork() {
        val payload = ByteArray(65_537) { it.toByte() }
        TlsFixture.server { socket ->
            serveUpgrade(socket)
            val input = socket.getInputStream()
            assertEquals(0x82, input.read())
            assertEquals(0xff, input.read())
            val size = input.exactly(8).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 255) }
            assertEquals(payload.size.toLong(), size)
            val mask = input.exactly(4)
            val data = input.exactly(size.toInt())
            assertArrayEquals(payload, ByteArray(data.size) { (data[it].toInt() xor mask[it and 3].toInt()).toByte() })
            socket.getOutputStream().apply { write(wsFrame(2, payload)); flush() }
        }.use { server ->
            SessionIo().use { io ->
                WebSocketTransport.connect("127.0.0.1", "localhost", io, server.port, TlsFixture.clientFactory).use { transport ->
                    transport.send(payload)
                    val received = java.io.ByteArrayOutputStream()
                    while (received.size() < payload.size) {
                        val part = transport.receive()!!; assertTrue(part.size <= STREAM_CHUNK_BYTES); received.write(part)
                    }
                    assertArrayEquals(payload, received.toByteArray())
                }
            }
            server.assertSuccess()
        }
    }

    @Test fun fragmentsAndControlFramesPreserveOneContinuousByteStream() {
        LocalServer { socket ->
            serveUpgrade(socket)
            socket.getOutputStream().apply {
                write(wsFrame(2, "abc".toByteArray(), false)); write(wsFrame(9, byteArrayOf(7)))
                write(wsFrame(0, "def".toByteArray())); write(wsFrame(2, "ghi".toByteArray())); flush()
            }
            val input = socket.getInputStream()
            assertEquals(0x8a, input.read()); assertEquals(0x81, input.read())
            val mask = input.exactly(4); assertEquals(7, (input.read() xor mask[0].toInt()) and 255)
        }.use { server ->
            SessionIo().use { io ->
                val socket = io.track(Socket("127.0.0.1", server.port))
                WebSocketTransport.upgrade(socket, "localhost", io).use { transport ->
                    assertEquals("abc", transport.receive()!!.toString(Charsets.UTF_8))
                    assertEquals("def", transport.receive()!!.toString(Charsets.UTF_8))
                    assertEquals("ghi", transport.receive()!!.toString(Charsets.UTF_8))
                }
            }
            server.assertSuccess()
        }
    }

    @Test fun rejectsMalformedFramesWithoutReadingDeclaredBodies() {
        val invalidFrames = listOf(
            byteArrayOf(0x82.toByte(), 0x80.toByte()), // Servers may not mask.
            byteArrayOf(0xc2.toByte(), 0), // No negotiated extension.
            byteArrayOf(0x81.toByte(), 0), // Text is outside the binary subprotocol.
            byteArrayOf(0x80.toByte(), 0), // Unexpected continuation.
            byteArrayOf(0x09, 0), // Fragmented ping.
            byteArrayOf(0x89.toByte(), 126, 0, 126),
            byteArrayOf(0x82.toByte(), 126, 0, 1), // Non-minimal length.
            byteArrayOf(0x82.toByte(), 127, 0, 0, 0, 0, 1, 0, 0, 1), // >16 MiB.
            byteArrayOf(0x88.toByte(), 1, 0),
            wsFrame(8, byteArrayOf(3, 0xee.toByte())), // Forbidden close1006.
            wsFrame(8, byteArrayOf(3, 0xe8.toByte(), 0xff.toByte())), // InvalidUTF8.
            wsFrame(2, byteArrayOf(1), false) + wsFrame(2, byteArrayOf(2)),
        )
        for (frame in invalidFrames) {
            LocalServer { socket -> serveUpgrade(socket); socket.getOutputStream().apply { write(frame); flush() } }.use { server ->
                SessionIo().use { io ->
                    WebSocketTransport.upgrade(io.track(Socket("127.0.0.1", server.port)), "localhost", io).use { transport ->
                        try { repeat(3) { transport.receive() }; fail(frame.contentToString()) } catch (_: ProtocolException) {}
                    }
                }
                server.assertSuccess()
            }
        }
    }
}

internal fun serveUpgrade(socket: Socket) {
    val input = socket.getInputStream()
    val text = StringBuilder()
    while (!text.endsWith("\r\n\r\n")) { val value = input.read(); if (value < 0) throw java.io.EOFException(); text.append(value.toChar()); check(text.length < 32 * 1024) }
    val key = text.lines().first { it.startsWith("Sec-WebSocket-Key:") }.substringAfter(':').trim()
    socket.getOutputStream().apply { write(upgradeResponse(key).toByteArray(Charsets.US_ASCII)); flush() }
}
internal fun upgradeResponse(key: String): String {
    val accept = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").toByteArray(Charsets.US_ASCII)))
    return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: $accept\r\nSec-WebSocket-Protocol: binary\r\n\r\n"
}
internal fun wsFrame(opcode: Int, bytes: ByteArray, fin: Boolean = true): ByteArray {
    val result = java.io.ByteArrayOutputStream()
    result.write((if (fin) 0x80 else 0) or opcode)
    when {
        bytes.size < 126 -> result.write(bytes.size)
        bytes.size < 65536 -> { result.write(126); result.write(bytes.size ushr 8); result.write(bytes.size) }
        else -> { result.write(127); repeat(4) { result.write(0) }; for (shift in 24 downTo 0 step 8) result.write(bytes.size ushr shift) }
    }
    result.write(bytes)
    return result.toByteArray()
}
