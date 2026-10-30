package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.net.Socket
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLContext

class UpdateTransportTest {
    private fun request(peer: Socket): String {
        val reader = peer.getInputStream().bufferedReader(Charsets.US_ASCII)
        val first = reader.readLine()
        while (!reader.readLine().isNullOrEmpty()) {}
        return first
    }
    private fun reply(peer: Socket, data: ByteArray, declared: Int = data.size, status: String = "200 OK", extra: String = "") {
        peer.getOutputStream().apply {
            write("HTTP/1.1 $status\r\nContent-Length: $declared\r\n${extra}Connection: close\r\n\r\n".toByteArray())
            write(data); flush()
        }
    }
    private fun transport(port: Int, timeout: Int = 3000) = HttpsUpdateTransport("https://localhost:$port", TlsFixture.clientFactory, timeout, timeout)
    private fun directory(): File = Files.createTempDirectory("tg-update-test-").toRealPath().toFile()
    private fun reject(code: UpdateFailureCode, action: () -> Unit) {
        try { action(); fail("Invalid update transfer accepted") }
        catch (failure: UpdateException) { assertEquals(code, failure.code); assertNull(failure.cause) }
    }

    @Test fun realHttpsMetadataUsesExactPathAndVerifiedTls() {
        val bytes = UpdateFixture.signed()
        TlsFixture.server { peer ->
            assertEquals("GET /android-dev/latest.json HTTP/1.1", request(peer)); reply(peer, bytes)
        }.use { server ->
            assertArrayEquals(bytes, transport(server.port).fetchManifest()); server.assertSuccess()
        }
    }

    @Test fun exactApkBecomesReadyOnlyAfterWholeHashAndProgress() {
        val bytes = ByteArray(180_000) { (it % 251).toByte() }
        val manifest = UpdateFixture.verified(bytes)
        val directory = directory(); val target = File(directory, "ready.apk")
        val progress = mutableListOf<Pair<Long, Long>>()
        try {
            TlsFixture.server { peer ->
                assertEquals("GET ${manifest.apkPath} HTTP/1.1", request(peer)); reply(peer, bytes)
            }.use { server ->
                transport(server.port).download(manifest, target, progress = { done, total ->
                    assertFalse(target.exists()); progress += done to total
                }); server.assertSuccess()
            }
            assertArrayEquals(bytes, target.readBytes())
            assertEquals(0L, progress.first().first); assertEquals(bytes.size.toLong(), progress.last().first)
            assertTrue(progress.all { it.second == bytes.size.toLong() }); assertTrue(progress.size > 2)
            assertEquals(listOf("ready.apk"), directory.list()!!.toList())
        } finally { directory.deleteRecursively() }
    }

    @Test fun corruptOrTruncatedApkIsDeletedInsteadOfPublished() {
        for (truncated in listOf(false, true)) {
            val bytes = ByteArray(1024) { 1 }; val manifest = UpdateFixture.verified(bytes)
            val directory = directory(); val target = File(directory, "ready.apk")
            try {
                TlsFixture.server { peer ->
                    request(peer); reply(peer, if (truncated) bytes.copyOf(512) else ByteArray(1024) { 2 }, declared = 1024)
                }.use { server ->
                    reject(if (truncated) UpdateFailureCode.SIZE else UpdateFailureCode.HASH) { transport(server.port).download(manifest, target) }
                    server.assertSuccess()
                }
                assertFalse(target.exists()); assertTrue(directory.list()!!.isEmpty())
            } finally { directory.deleteRecursively() }
        }
    }

    @Test fun declaredSizeMismatchAndOversizeMetadataFailBeforeWritingBody() {
        val bytes = "fixture".toByteArray(); val manifest = UpdateFixture.verified(bytes)
        val directory = directory(); val target = File(directory, "ready.apk")
        try {
            TlsFixture.server { peer -> request(peer); reply(peer, ByteArray(0), declared = bytes.size + 1) }.use { server ->
                reject(UpdateFailureCode.SIZE) { transport(server.port).download(manifest, target) }; server.assertSuccess()
            }
            TlsFixture.server { peer -> request(peer); reply(peer, ByteArray(0), declared = 16 * 1024 + 1) }.use { server ->
                reject(UpdateFailureCode.SIZE) { transport(server.port).fetchManifest() }; server.assertSuccess()
            }
            assertTrue(directory.list()!!.isEmpty())
        } finally { directory.deleteRecursively() }
    }

    @Test fun redirectsAndAmbiguousFramingAreRejected() {
        val variants = listOf("302 Found" to "Location: https://attacker.invalid/apk\r\n", "200 OK" to "Transfer-Encoding: chunked\r\n",
            "200 OK" to "Content-Length: 1\r\n", "200 OK" to "cOnTeNt-LeNgTh: 1\r\n",
            "200 OK" to "Content-Encoding: gzip\r\n", "200 OK" to "X-Note: one\r\nX-Note: two\r\n")
        for ((status, extra) in variants) {
            TlsFixture.server { peer -> request(peer); reply(peer, byteArrayOf(1), status = status, extra = extra) }.use { server ->
                reject(UpdateFailureCode.HTTP) { transport(server.port).fetchManifest() }; server.assertSuccess()
            }
        }
    }

    @Test fun platformHttpStillRejectsOversizedHeadersAndMissingLength() {
        val variants = listOf(
            "Content-Length: 1\r\nX-Note: ${"a".repeat(9000)}\r\n",
            "Content-Length: 1\r\n" + (1..33).joinToString("") { "X-Header-$it: value\r\n" },
            "X-Note: no-length\r\n",
        )
        for (headers in variants) {
            TlsFixture.server { peer ->
                request(peer)
                peer.getOutputStream().apply {
                    write(("HTTP/1.1 200 OK\r\n" + headers + "Connection: close\r\n\r\na").toByteArray())
                    flush()
                }
            }.use { server ->
                reject(UpdateFailureCode.HTTP) { transport(server.port).fetchManifest() }
                server.assertSuccess()
            }
        }
    }

    @Test fun platformDownloadCancellationAfterPartialBytesNeverPublishesApk() {
        val cancel = AtomicBoolean(false)
        val closed = CountDownLatch(1)
        val bytes = ByteArray(128_000) { 7 }
        val directory = directory(); val target = File(directory, "ready.apk")
        try {
            TlsFixture.server { peer ->
                request(peer)
                reply(peer, bytes.copyOf(4096), declared = bytes.size)
                try { peer.getInputStream().read() } catch (_: Exception) {} finally { closed.countDown() }
            }.use { server ->
                reject(UpdateFailureCode.CANCELLED) {
                    transport(server.port).download(UpdateFixture.verified(bytes), target, cancel::get) { received, _ ->
                        if (received > 0) cancel.set(true)
                    }
                }
                assertTrue(closed.await(1, TimeUnit.SECONDS)); server.assertSuccess()
            }
            assertFalse(target.exists())
            assertTrue(directory.list()!!.isEmpty())
        } finally { directory.deleteRecursively() }
    }

    @Test fun untrustedCertificateCannotBeBypassed() {
        TlsFixture.server { peer -> try { request(peer) } catch (_: Exception) {} }.use { server ->
            val transport = HttpsUpdateTransport("https://localhost:${server.port}", SSLContext.getDefault().socketFactory, 3000, 3000)
            reject(UpdateFailureCode.TLS) { transport.fetchManifest() }
        }
    }

    @Test fun cancellationClosesPendingReadAndRemovesPartialFile() {
        val cancel = AtomicBoolean(false); val closed = CountDownLatch(1)
        val bytes = ByteArray(4096); val directory = directory(); val target = File(directory, "ready.apk")
        try {
            TlsFixture.server { peer ->
                request(peer); reply(peer, ByteArray(0), declared = bytes.size)
                cancel.set(true)
                try { assertEquals(-1, peer.getInputStream().read()) } catch (_: Exception) {} finally { closed.countDown() }
            }.use { server ->
                reject(UpdateFailureCode.CANCELLED) { transport(server.port).download(UpdateFixture.verified(bytes), target, cancel::get) }
                assertTrue(closed.await(1, TimeUnit.SECONDS)); server.assertSuccess()
            }
            assertTrue(directory.list()!!.isEmpty())
        } finally { directory.deleteRecursively() }
    }

    @Test fun overallDeadlineStopsSilentServerAndCleansPartialFile() {
        val directory = directory(); val target = File(directory, "ready.apk")
        try {
            TlsFixture.server { peer ->
                request(peer)
                try { peer.getInputStream().read() } catch (_: Exception) {}
            }.use { server ->
                val start = System.nanoTime()
                reject(UpdateFailureCode.TIMEOUT) { transport(server.port, 800).download(UpdateFixture.verified(), target) }
                assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 2200)
            }
            assertTrue(directory.list()!!.isEmpty())
        } finally { directory.deleteRecursively() }
    }

    @Test fun existingDestinationIsPreservedAndPreCancelledRequestDoesNotConnect() {
        val directory = directory(); val target = File(directory, "ready.apk").apply { writeText("preserve") }
        try {
            reject(UpdateFailureCode.FILE) { HttpsUpdateTransport().download(UpdateFixture.verified(), target) }
            assertEquals("preserve", target.readText())
            reject(UpdateFailureCode.CANCELLED) { HttpsUpdateTransport().fetchManifest { true } }
        } finally { directory.deleteRecursively() }
    }
}
