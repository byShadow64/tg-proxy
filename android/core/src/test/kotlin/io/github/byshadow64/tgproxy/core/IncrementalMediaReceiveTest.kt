package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** A real TLS peer withholds the body tail until the first bytes reach its consumer. */
class IncrementalMediaReceiveTest {
    @Test fun websocketForwardsAvailablePrefixBeforeTheRestOfItsFrame() {
        val payload = ByteArray(160_003) { (it * 31).toByte() }
        val prefixObserved = CountDownLatch(1)
        val prefixBytes = 1_024
        TlsFixture.server { socket ->
            serveUpgrade(socket)
            val frame = wsFrame(2, payload)
            val headerBytes = frame.size - payload.size
            socket.getOutputStream().apply {
                write(frame, 0, headerBytes + prefixBytes); flush()
                assertTrue("Consumer must not wait for a full64KiB batch", prefixObserved.await(2, TimeUnit.SECONDS))
                write(frame, headerBytes + prefixBytes, frame.size - headerBytes - prefixBytes); flush()
            }
        }.use { server ->
            SessionIo().use { io ->
                WebSocketTransport.connect("127.0.0.1", "localhost", io, server.port, TlsFixture.clientFactory).use { transport ->
                    assertIncrementalAndComplete(transport, payload, prefixBytes, prefixObserved)
                }
            }
            server.assertSuccess()
        }
    }

    @Test fun helperForwardsAvailablePrefixBeforeTheRestOfItsFrame() {
        val payload = ByteArray(160_003) { (it * 17).toByte() }
        val prefixObserved = CountDownLatch(1)
        val prefixBytes = 1_024
        TlsFixture.server { socket ->
            readHelper(socket); readHelper(socket); writeHelper(socket, "OK".toByteArray())
            socket.getOutputStream().apply {
                write(byteArrayOf((payload.size ushr 24).toByte(), (payload.size ushr 16).toByte(),
                    (payload.size ushr 8).toByte(), payload.size.toByte()))
                write(payload, 0, prefixBytes); flush()
                assertTrue("Consumer must not wait for a full64KiB batch", prefixObserved.await(2, TimeUnit.SECONDS))
                write(payload, prefixBytes, payload.size - prefixBytes); flush()
            }
        }.use { server ->
            SessionIo().use { io ->
                HelperTransport.connect(HelperSettings("127.0.0.1", server.port, TlsFixture.pin,
                    "incremental-local-fixture-token".repeat(2)), "kws2-1.web.telegram.org", io).use { transport ->
                    assertIncrementalAndComplete(transport, payload, prefixBytes, prefixObserved)
                }
            }
            server.assertSuccess()
        }
    }

    private fun assertIncrementalAndComplete(transport: BinaryTransport, payload: ByteArray,
                                            prefixBytes: Int, prefixObserved: CountDownLatch) {
        val received = java.io.ByteArrayOutputStream()
        try {
            while (received.size() < prefixBytes) {
                val chunk = transport.receive()!!
                assertTrue(chunk.isNotEmpty() && chunk.size <= prefixBytes - received.size())
                received.write(chunk)
            }
            assertArrayEquals(payload.copyOfRange(0, prefixBytes), received.toByteArray())
        } finally {
            prefixObserved.countDown()
        }
        while (received.size() < payload.size) {
            val chunk = transport.receive()!!
            assertTrue(chunk.isNotEmpty() && chunk.size <= STREAM_CHUNK_BYTES)
            received.write(chunk)
        }
        assertArrayEquals(payload, received.toByteArray())
    }
}
