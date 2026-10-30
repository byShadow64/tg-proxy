package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLSocketFactory

class ResourceBoundsTest {
    @Test fun numericIpv4BypassesBusyHostnameResolversAndRejectsMalformedNumericAddresses() {
        val executor = BoundedDns::class.java.getDeclaredField("executor").apply { isAccessible = true }.get(BoundedDns) as java.util.concurrent.ThreadPoolExecutor
        val entered = CountDownLatch(2)
        val release = CountDownLatch(1)
        try {
            repeat(2) { executor.execute { entered.countDown(); release.await() } }
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            for (host in listOf("127.0.0.1", "149.154.167.220", "192.168.1.20", "0.0.0.0", "255.255.255.255")) {
                SessionIo().use { io -> assertEquals(host, BoundedDns.resolve(host, io).hostAddress) }
            }
            for (host in listOf("256.1.2.3", "1.2.3", "1.2.3.4.5", "1..2.3", "123", "0000.1.2.3", "")) {
                try { BoundedDns.ipv4Literal(host); fail(host) } catch (_: java.net.UnknownHostException) {}
            }
            assertNull(BoundedDns.ipv4Literal("helper.example"))
        } finally { release.countDown() }
    }

    @Test fun sessionAndUplinkExecutorFactoryHasFixedQueueAndRejectsOverflow() {
        for (kind in listOf("session", "uplink")) {
            val executor = ProxyEngine.boundedExecutor(1, kind)
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            try {
                executor.execute { entered.countDown(); release.await() }
                assertTrue(entered.await(1, TimeUnit.SECONDS))
                executor.execute { }
                assertEquals(1, executor.queue.size)
                assertEquals(0, executor.queue.remainingCapacity())
                try { executor.execute { }; fail() } catch (_: RejectedExecutionException) {}
                assertEquals(1, executor.poolSize)
                assertEquals(1, executor.queue.size)
            } finally { release.countDown(); executor.shutdownNow(); assertTrue(executor.awaitTermination(1, TimeUnit.SECONDS)) }
        }
    }

    @Test fun tlsHandshakeFailureClosesFirstRouteBeforeSessionCanUseSecondRoute() {
        val failedClosed = CountDownLatch(1)
        LocalServer { socket ->
            assertTrue(socket.getInputStream().read() >= 0)
            socket.getOutputStream().apply { write("INVALID TLS".toByteArray()); flush() }
            try { while (socket.getInputStream().read() >= 0) { } }
            catch (_: java.net.SocketException) { /* A reset also proves the first descriptor was closed. */ }
            finally { failedClosed.countDown() }
        }.use { first ->
            SessionIo().use { io ->
                try { tlsConnect("127.0.0.1", first.port, io, "localhost", TlsFixture.clientFactory); fail() }
                catch (_: javax.net.ssl.SSLException) {}
                assertFalse(io.closed)
                assertTrue(failedClosed.await(1, TimeUnit.SECONDS))
                TlsFixture.server { socket ->
                    serveUpgrade(socket)
                    socket.getOutputStream().apply { write(wsFrame(2, "second-route".toByteArray())); flush() }
                }.use { second ->
                    WebSocketTransport.connect("127.0.0.1", "localhost", io, second.port, TlsFixture.clientFactory).use { transport ->
                        assertEquals("second-route", transport.receive()!!.toString(Charsets.US_ASCII))
                    }
                    second.assertSuccess()
                }
            }
            first.assertSuccess()
        }
    }

    @Test fun tlsWrappingFailureClosesAlreadyConnectedRawSocket() {
        val closed = CountDownLatch(1)
        LocalServer { socket -> assertEquals(-1, socket.getInputStream().read()); closed.countDown() }.use { server ->
            SessionIo().use { io ->
                val failing = object : SSLSocketFactory() {
                    override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean): Socket = throw java.io.IOException()
                    override fun createSocket(host: String?, port: Int): Socket = throw UnsupportedOperationException()
                    override fun createSocket(host: String?, port: Int, localHost: java.net.InetAddress?, localPort: Int): Socket = throw UnsupportedOperationException()
                    override fun createSocket(host: java.net.InetAddress?, port: Int): Socket = throw UnsupportedOperationException()
                    override fun createSocket(address: java.net.InetAddress?, port: Int, localAddress: java.net.InetAddress?, localPort: Int): Socket = throw UnsupportedOperationException()
                    override fun getDefaultCipherSuites(): Array<String> = emptyArray()
                    override fun getSupportedCipherSuites(): Array<String> = emptyArray()
                }
                try { tlsConnect("127.0.0.1", server.port, io, "localhost", failing); fail() }
                catch (_: java.io.IOException) {}
                assertFalse(io.closed)
                assertTrue(closed.await(1, TimeUnit.SECONDS))
            }
            server.assertSuccess()
        }
    }
}
