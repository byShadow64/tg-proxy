package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Exercise partial receive() through the actual engine's two continuous AES-CTR contexts. */
class IncrementalReqPqTest {
    @Test fun partialTlsFrameReachesClientBeforeTailAndPreservesAnonymousReplyForAllProtocols() {
        for (protocol in TransportProtocol.entries) for (media in listOf(false, true)) {
            val prefixObserved = CountDownLatch(1)
            val secret = ByteArray(16) { 0x36 }
            val nonce = ByteArray(16) { (it * 13 + 1).toByte() }
            val body = le(0x05162463) + nonce + ByteArray(16) { 7 } +
                byteArrayOf(1, 1, 0, 0) + le(0x1cb5c415) + le(0)
            val message = ByteArray(8) + ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(1).array() +
                le(body.size) + body
            val expected = frame(protocol, message)
            TlsFixture.server { socket ->
                serveUpgrade(socket)
                val init = readClientWs(socket).second
                assertEquals(64, init.size)
                val decrypt = ctr(init.copyOfRange(8, 40), init.copyOfRange(40, 56))
                val decoded = decrypt.update(init)
                assertTrue((56..59).all { decoded[it].toInt() and 255 == protocol.tag })
                assertEquals(if (media) -3 else 3,
                    ByteBuffer.wrap(decoded, 60, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt())
                val request = decrypt.update(readClientWs(socket).second)
                val header = if (protocol == TransportProtocol.ABRIDGED) 1 else 4
                assertArrayEquals(nonce, request.copyOfRange(header + 24, header + 40))
                val reverse = init.copyOfRange(8, 56).reversedArray()
                val encrypted = ctr(reverse.copyOfRange(0, 32), reverse.copyOfRange(32, 48)).update(expected)
                val wire = wsFrame(2, encrypted)
                val headerBytes = wire.size - encrypted.size
                socket.getOutputStream().apply {
                    // Three bytes deliberately split the transport length and the AES block.
                    write(wire, 0, headerBytes + 3); flush()
                    assertTrue("Engine must forward a partial encrypted reply before the rest exists",
                        prefixObserved.await(2, TimeUnit.SECONDS))
                    var offset = headerBytes + 3
                    for (count in listOf(1, 2, 5, 15, 16, 17)) {
                        if (offset + count >= wire.size) break
                        write(wire, offset, count); flush(); offset += count
                    }
                    write(wire, offset, wire.size - offset); flush()
                }
                socket.getInputStream().read()
            }.use { server ->
                val connector: (ClientHandshake, SessionIo) -> BinaryTransport = { _, io ->
                    WebSocketTransport.connect("127.0.0.1", "localhost", io, server.port, TlsFixture.clientFactory)
                }
                val port = freePort()
                ProxyEngine(EngineConfig(port, "36".repeat(16)), connector).use { engine ->
                    engine.start()
                    Socket("127.0.0.1", port).use { client ->
                        client.soTimeout = 3000
                        val init = clientInit(secret, protocol, if (media) -3 else 3)
                        val upload = ctr(sha(init.copyOfRange(8, 40) + secret), init.copyOfRange(40, 56))
                        upload.update(ByteArray(64))
                        val requestBody = le(0xbe7e8ef1.toInt()) + nonce
                        val request = frame(protocol, ByteArray(16) + le(requestBody.size) + requestBody)
                        client.getOutputStream().apply { write(init); write(upload.update(request)); flush() }
                        val reverse = init.copyOfRange(8, 56).reversedArray()
                        val download = ctr(sha(reverse.copyOfRange(0, 32) + secret), reverse.copyOfRange(32, 48))
                        val prefix = try {
                            download.update(client.getInputStream().exactly(3)).also {
                                assertArrayEquals(expected.copyOfRange(0, 3), it)
                            }
                        } finally { prefixObserved.countDown() }
                        val rest = download.update(client.getInputStream().exactly(expected.size - prefix.size))
                        assertArrayEquals("Partial response must preserve length, resPQ and nonce", expected, prefix + rest)
                    }
                }
                server.assertSuccess()
            }
        }
    }

    private fun frame(protocol: TransportProtocol, message: ByteArray) =
        if (protocol == TransportProtocol.ABRIDGED) byteArrayOf((message.size / 4).toByte()) + message
        else le(message.size) + message
    private fun le(value: Int) = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array()
    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
    private fun ctr(key: ByteArray, iv: ByteArray) = Cipher.getInstance("AES/CTR/NoPadding").apply {
        init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
    }
}
