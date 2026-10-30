package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class IdleAndRoutingTest {
    @Test fun websocketCanIdleWithoutDeadlineButPartialFrameStillTimesOut() {
        for (partial in listOf(false, true)) {
            val ready = CountDownLatch(1); val release = CountDownLatch(1)
            LocalServer { socket ->
                serveUpgrade(socket)
                if (partial) socket.getOutputStream().apply { write(0x82); flush() }
                ready.countDown(); release.await()
                if (!partial) socket.getOutputStream().apply { write(wsFrame(2, byteArrayOf(42))); flush() }
            }.use { server ->
                SessionIo().use { io ->
                    WebSocketTransport.upgrade(io.track(Socket("127.0.0.1", server.port)), "localhost", io).use { transport ->
                        val result = AtomicReference<ByteArray?>(); val done = CountDownLatch(1)
                        val reader = Thread { try { result.set(transport.receive()) } catch (_: Exception) {} finally { done.countDown() } }.apply { isDaemon = true; start() }
                        assertTrue(ready.await(1, TimeUnit.SECONDS))
                        if (partial) await { deadlines(io).contains("ws-frame") }
                        io.expire(Long.MAX_VALUE)
                        assertEquals(partial, io.closed)
                        if (partial) { assertTrue(io.timedOut); assertEquals(EngineStage.FRAME_PROGRESS, io.failureStage) }
                        release.countDown(); assertTrue(done.await(2, TimeUnit.SECONDS))
                        if (!partial) assertArrayEquals(byteArrayOf(42), result.get())
                        reader.join(100)
                    }
                }
                server.assertSuccess()
            }
        }
    }

    @Test fun helperCanIdleWithoutDeadlineButPartialLengthStillTimesOut() {
        for (partial in listOf(false, true)) {
            val ready = CountDownLatch(1); val release = CountDownLatch(1)
            TlsFixture.server { socket ->
                readHelper(socket); readHelper(socket); writeHelper(socket, "OK".toByteArray())
                if (partial) socket.getOutputStream().apply { write(0); flush() }
                ready.countDown(); release.await()
                if (!partial) writeHelper(socket, byteArrayOf(43))
            }.use { server ->
                SessionIo().use { io ->
                    HelperTransport.connect(HelperSettings("127.0.0.1", server.port, TlsFixture.pin, "local-fixture-token".repeat(3)), "kws2.web.telegram.org", io).use { transport ->
                        val result = AtomicReference<ByteArray?>(); val done = CountDownLatch(1)
                        Thread { try { result.set(transport.receive()) } catch (_: Exception) {} finally { done.countDown() } }.apply { isDaemon = true; start() }
                        assertTrue(ready.await(1, TimeUnit.SECONDS))
                        if (partial) await { deadlines(io).contains("helper-frame") }
                        io.expire(Long.MAX_VALUE); assertEquals(partial, io.closed)
                        release.countDown(); assertTrue(done.await(2, TimeUnit.SECONDS))
                        if (!partial) assertArrayEquals(byteArrayOf(43), result.get())
                    }
                }
                server.assertSuccess()
            }
        }
    }

    @Test fun setupTimeoutAbortsOnlyAttemptAndLeavesSessionAvailableForNextRoute() {
        LocalServer { socket -> while (socket.getInputStream().read() >= 0) {} }.use { server ->
            SessionIo().use { io ->
                val socket = io.track(Socket("127.0.0.1", server.port))
                val done = CountDownLatch(1)
                Thread {
                    try { io.operation("tls", 1, socket) { socket.getInputStream().read() } }
                    catch (failure: Exception) { assertTrue(failure is java.net.SocketTimeoutException) }
                    finally { done.countDown() }
                }.apply { isDaemon = true; start() }
                await { deadlines(io).contains("tls") }
                io.expire(Long.MAX_VALUE)
                assertTrue(done.await(1, TimeUnit.SECONDS)); assertFalse(io.closed); assertFalse(io.timedOut); assertTrue(socket.isClosed)
                assertEquals(EngineStage.TLS, io.failureStage)
            }
            server.assertSuccess()
        }
    }

    @Test fun firstReplyDeadlineRequiresTrafficAndIsCanceledByResponse() {
        SessionIo().use { idle -> idle.expire(Long.MAX_VALUE); assertFalse(idle.closed) }
        SessionIo().use { pending -> pending.expectFirstReply(); pending.expire(Long.MAX_VALUE); assertTrue(pending.timedOut); assertEquals(EngineStage.FIRST_REPLY, pending.failureStage) }
        SessionIo().use { replied -> replied.expectFirstReply(); replied.receivedFirstReply(); replied.expire(Long.MAX_VALUE); assertFalse(replied.closed) }
    }

    @Test fun routeCacheRequiresResponseIsPerDcAndMediaAndInvalidatesOnFailure() {
        val attempts = mutableListOf<DirectRoute>()
        val fake = object : BinaryTransport { override fun send(bytes: ByteArray) {}; override fun receive(): ByteArray? = null; override fun close() {} }
        val planner = DirectRoutePlanner({ route, _ -> attempts += route; fake })
        val normal = ClientHandshake(2, false, TransportProtocol.INTERMEDIATE, ByteArray(48))
        val media = normal.copy(media = true)
        val mediaRoute = planner.plan(media).first { it.strategy == DirectStrategy.FIXED_IP }
        assertEquals(DirectStrategy.OFFICIAL_DNS, planner.plan(media).first().strategy)
        assertEquals(DirectStrategy.FIXED_IP, planner.plan(normal).first().strategy)
        planner.confirm(mediaRoute)
        assertEquals(mediaRoute, planner.plan(media).first()); assertEquals(DirectStrategy.FIXED_IP, planner.plan(normal).first().strategy)
        planner.fail(mediaRoute)
        assertFalse(planner.plan(media).contains(mediaRoute))
        SessionIo().use { io -> planner.connect(media, io).use { connected ->
            assertEquals(attempts.single(), connected.route)
            // Merely connecting did not install a cache entry; only this explicit response confirmation does.
            connected.confirmedResponse(); assertEquals(connected.route, planner.plan(media).first())
        } }
    }

    @Test fun frontingIdentityCannotAcceptCamouflageOrArbitraryCaIssuedCertificate() {
        assertTrue(matchesTelegramName("telegram.org", "telegram.org"))
        assertTrue(matchesTelegramName("*.web.telegram.org", "kws2.web.telegram.org"))
        assertFalse(matchesTelegramName("*.telegram.org", "kws2.web.telegram.org"))
        assertFalse(matchesTelegramName("*.org", "telegram.org"))
        assertFalse(matchesTelegramName("sprinthost.ru", "kws2.web.telegram.org"))
        // The fixture identifies localhost only; even a separately trusted chain cannot identify Telegram.
        val certificate = TlsFixture::class.java.getDeclaredField("certificate").apply { isAccessible = true }.get(TlsFixture) as java.security.cert.X509Certificate
        try { verifyTelegramIdentity(certificate, "kws2.web.telegram.org"); fail() } catch (_: javax.net.ssl.SSLPeerUnverifiedException) {}
        try { verifyTelegramIdentity(certificate, "attacker.example"); fail() } catch (_: javax.net.ssl.SSLPeerUnverifiedException) {}
    }
}

internal fun deadlines(io: SessionIo): Set<*> = (SessionIo::class.java.getDeclaredField("deadlines").apply { isAccessible = true }.get(io) as Map<*, *>).keys
