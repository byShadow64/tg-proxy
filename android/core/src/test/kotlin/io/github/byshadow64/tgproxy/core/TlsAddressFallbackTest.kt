package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class TlsAddressFallbackTest {
    private fun address(last: Int) = InetAddress.getByAddress(byteArrayOf(127, 0, 0, last.toByte()))

    @Test fun failedFirstDnsAddressFallsThroughToRealAuthenticatedTlsConnection() {
        TlsFixture.server { peer ->
            assertEquals(42, peer.getInputStream().read())
            peer.getOutputStream().apply { write(43); flush() }
        }.use { server ->
            SessionIo().use { io ->
                tlsConnect("synthetic.invalid", server.port, io, "localhost", TlsFixture.clientFactory,
                    resolve = { _, _, _ -> listOf(address(2), address(1)) }).use { socket ->
                    socket.getOutputStream().apply { write(42); flush() }
                    assertEquals(43, socket.getInputStream().read())
                }
            }
            server.assertSuccess()
        }
    }

    @Test fun authenticationFailureIsNotReplacedByAnotherAddressAttempt() {
        val closed = CountDownLatch(1)
        TlsFixture.server { peer ->
            try { peer.getInputStream().read() } catch (_: javax.net.ssl.SSLException) {}
            finally { closed.countDown() }
        }.use { server ->
            SessionIo().use { io ->
                try {
                    tlsConnect("synthetic.invalid", server.port, io, "wrong.invalid", TlsFixture.clientFactory,
                        resolve = { _, _, _ -> listOf(address(1), address(2)) })
                    fail("The first certificate does not identify the requested host")
                } catch (_: javax.net.ssl.SSLHandshakeException) {}
                assertFalse(io.closed)
                assertTrue(closed.await(1, TimeUnit.SECONDS))
            }
        }
    }

    @Test fun addressAttemptsAreDeduplicatedBoundedAndFailedSocketsAreClosed() {
        val attempts = mutableListOf<Pair<InetSocketAddress, Int>>()
        val sockets = mutableListOf<Socket>()
        SessionIo().use { io ->
            try {
                connectResolvedAddresses((1..20).flatMap { listOf(address(it), address(it)) }, 443, io,
                    System.nanoTime() + TimeUnit.SECONDS.toNanos(30)) {
                    object : Socket() {
                        override fun connect(endpoint: SocketAddress, timeout: Int) {
                            attempts += endpoint as InetSocketAddress to timeout
                            throw ConnectException()
                        }
                    }.also { sockets += it }
                }
                fail()
            } catch (_: ConnectException) {}
            assertEquals(8, attempts.size)
            assertEquals((1..8).map { address(it) }, attempts.map { it.first.address })
            assertTrue(attempts.dropLast(1).all { it.second in 1..1_500 })
            assertTrue(attempts.last().second in 1..CONNECT_TIMEOUT_MS)
            assertTrue(sockets.all { it.isClosed })
            assertFalse(io.closed)
        }
    }

    @Test fun tcpAttemptsShareOneDeadlineInsteadOfRestartingTimeoutForEveryAddress() {
        val attempts = AtomicInteger()
        val sockets = mutableListOf<Socket>()
        SessionIo().use { io ->
            val start = System.nanoTime()
            try {
                connectResolvedAddresses(listOf(address(1), address(2), address(3)), 443, io,
                    start + TimeUnit.MILLISECONDS.toNanos(120)) {
                    object : Socket() {
                        override fun connect(endpoint: SocketAddress, timeout: Int) {
                            if (attempts.incrementAndGet() == 1) throw ConnectException()
                            Thread.sleep(timeout.toLong())
                            throw SocketTimeoutException()
                        }
                    }.also { sockets += it }
                }
                fail()
            } catch (_: SocketTimeoutException) {}
            assertEquals(2, attempts.get())
            assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 500)
            assertTrue(sockets.all { it.isClosed })
        }
    }

    @Test fun cancellationClosesCurrentTcpAttemptAndDoesNotTryOtherAddresses() {
        val entered = CountDownLatch(1)
        val attempts = AtomicInteger()
        val worker = Executors.newSingleThreadExecutor()
        SessionIo().use { io ->
            try {
                val result = worker.submit<Boolean> {
                    try {
                        connectResolvedAddresses(listOf(address(1), address(2)), 443, io,
                            System.nanoTime() + TimeUnit.SECONDS.toNanos(10)) {
                            object : Socket() {
                                override fun connect(endpoint: SocketAddress, timeout: Int) {
                                    attempts.incrementAndGet(); entered.countDown()
                                    while (!isClosed) Thread.sleep(5)
                                    throw SocketException()
                                }
                            }
                        }
                        false
                    } catch (_: java.io.IOException) { true }
                }
                assertTrue(entered.await(1, TimeUnit.SECONDS))
                io.close()
                assertTrue(result.get(1, TimeUnit.SECONDS))
                assertEquals(1, attempts.get())
            } finally { worker.shutdownNow(); assertTrue(worker.awaitTermination(1, TimeUnit.SECONDS)) }
        }
    }

    @Test fun tlsSetupDeadlineAlsoLimitsWaitingForUninterruptibleDns() {
        val release = CountDownLatch(1)
        SharedHostResolver({
            while (release.count > 0) try { release.await() } catch (_: InterruptedException) {}
            listOf(address(1))
        }).use { resolver ->
            try {
                SessionIo().use { io ->
                    val start = System.nanoTime()
                    try {
                        tlsConnect("synthetic.invalid", 443, io, "localhost", TlsFixture.clientFactory,
                            timeoutMs = 100, resolve = resolver::resolveAll)
                        fail()
                    } catch (_: SocketTimeoutException) {}
                    assertEquals(EngineStage.DNS, io.failureStage)
                    assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 500)
                }
            } finally { release.countDown() }
        }
    }
}
