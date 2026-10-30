package io.github.byshadow64.tgproxy.core

import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Explicit opt-in public protocol diagnostic. Sends only unauthenticated req_pq_multi, never account/user traffic. */
class PublicTelegramProbeTest {
    @Test fun optInPublicRoundTripThroughRealLocalEngine() {
        assumeTrue("Set TGPROXY_PUBLIC_PROBE=1 explicitly to contact public Telegram WSS", System.getenv("TGPROXY_PUBLIC_PROBE") == "1")
        val allDataCenters = System.getenv("TGPROXY_PUBLIC_ALL_DCS") == "1"
        val jobs = mutableListOf<Probe>()
        if (allDataCenters) for (dc in 1..5) for (media in listOf(false, true)) jobs += Probe(dc, media, null, TransportProtocol.PADDED_INTERMEDIATE)
        else for (dc in listOf(2, 4)) for (media in listOf(false, true)) {
            for (strategy in listOf(DirectStrategy.OFFICIAL_DNS, DirectStrategy.FIXED_IP, DirectStrategy.FRONTED_IP)) jobs += Probe(dc, media, strategy, TransportProtocol.PADDED_INTERMEDIATE)
            WssRelayCatalog.domains.take(2).forEach { jobs += Probe(dc, media, DirectStrategy.RELAY_WSS, TransportProtocol.PADDED_INTERMEDIATE, it) }
            jobs += Probe(dc, media, null, TransportProtocol.PADDED_INTERMEDIATE)
        }
        if (!allDataCenters) {
            jobs += Probe(2, false, DirectStrategy.FIXED_IP, TransportProtocol.ABRIDGED)
            jobs += Probe(2, false, DirectStrategy.FIXED_IP, TransportProtocol.INTERMEDIATE)
        }
        val successes = AtomicInteger()
        val passed = java.util.concurrent.CopyOnWriteArrayList<Probe>()
        val pool = Executors.newFixedThreadPool(3)
        try {
            val futures = jobs.map { job -> pool.submit {
                val began = System.nanoTime()
                val result = try { runProbe(job); successes.incrementAndGet(); passed += job; "RES_PQ_MATCH" } catch (failure: Exception) { failure.javaClass.simpleName }
                println("{\"dc\":${job.dc},\"media\":${job.media},\"strategy\":\"${job.strategy?.name ?: "AUTOMATIC"}\",\"protocol\":\"${job.protocol}\",\"result\":\"$result\",\"ms\":${TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - began)}}")
            } }
            futures.forEach { it.get(120, TimeUnit.SECONDS) }
            assertTrue("No public req_pq_multi/resPQ round trip succeeded", successes.get() > 0)
            assertTrue("An automatic DC/media route failed the anonymous end-to-end probe", jobs.filter { it.strategy == null }.all { it in passed })
            if (!allDataCenters) for (dc in listOf(2, 4)) for (media in listOf(false, true)) assertTrue("No authenticated relay route returned resPQ", passed.any { it.dc == dc && it.media == media && it.strategy == DirectStrategy.RELAY_WSS })
        } finally { pool.shutdownNow(); pool.awaitTermination(5, TimeUnit.SECONDS) }
    }

    private data class Probe(val dc: Int, val media: Boolean, val strategy: DirectStrategy?, val protocol: TransportProtocol, val relayBase: String? = null)

    private fun runProbe(probe: Probe) {
        val random = SecureRandom()
        val secret = ByteArray(16).also(random::nextBytes)
        val secretHex = secret.joinToString("") { "%02x".format(it.toInt() and 255) }
        val port = freePort()
        val domain = if (probe.relayBase != null) "kws${probe.dc}.${probe.relayBase}" else "kws${probe.dc}${if (probe.media) "-1" else ""}.web.telegram.org"
        val host = if (probe.strategy in listOf(DirectStrategy.OFFICIAL_DNS, DirectStrategy.RELAY_WSS)) domain else "149.154.167.220"
        val connector: (ClientHandshake, SessionIo) -> BinaryTransport = { _, io ->
            WebSocketTransport.connect(host, domain, io, sni = if (probe.strategy == DirectStrategy.FRONTED_IP) "sprinthost.ru" else null, timeoutMs = 5_000)
        }
        val config = EngineConfig(port, secretHex, maxConnections = 1)
        val engine = if (probe.strategy == null) ProxyEngine(config) else ProxyEngine(config, connector)
        engine.use {
            engine.start()
            Socket("127.0.0.1", port).use { client ->
                client.soTimeout = 8_000
                val init = ByteArray(64).also(random::nextBytes)
                for (i in 56..59) init[i] = probe.protocol.tag.toByte()
                val signedDc = if (probe.media) -probe.dc else probe.dc
                init[60] = signedDc.toByte(); init[61] = (signedDc shr 8).toByte()
                val up = ctr(sha(init.copyOfRange(8, 40) + secret), init.copyOfRange(40, 56))
                val encryptedInit = up.update(init)
                val wireInit = init.copyOf().also { encryptedInit.copyInto(it, 56, 56, 64) }
                val reverse = init.copyOfRange(8, 56).reversedArray()
                val down = ctr(sha(reverse.copyOfRange(0, 32) + secret), reverse.copyOfRange(32, 48))
                val nonce = ByteArray(16).also(random::nextBytes)
                val body = little(0xbe7e8ef1.toInt()) + nonce
                val now = System.currentTimeMillis()
                val msgId = ((now / 1000) shl 32) or ((((now % 1000) shl 32) / 1000) and -4L)
                val message = ByteArray(8) + ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(msgId).array() + little(body.size) + body
                val packet = if (probe.protocol == TransportProtocol.ABRIDGED) byteArrayOf((message.size / 4).toByte()) + message else little(message.size) + message
                client.getOutputStream().apply { write(wireInit); write(up.update(packet)); flush() }
                fun plain(count: Int) = down.update(client.getInputStream().exactly(count))
                val length = if (probe.protocol == TransportProtocol.ABRIDGED) {
                    val first = plain(1)[0].toInt() and 255
                    if (first == 127 || first == 255) { val ext = plain(3); ((ext[0].toInt() and 255) or ((ext[1].toInt() and 255) shl 8) or ((ext[2].toInt() and 255) shl 16)) * 4 }
                    else (first and 127) * 4
                } else ByteBuffer.wrap(plain(4)).order(ByteOrder.LITTLE_ENDIAN).int and 0x7fff_ffff
                check(length in 40..1024 * 1024)
                val reply = plain(length)
                check(reply.copyOfRange(0, 8).contentEquals(ByteArray(8)))
                val responseLength = ByteBuffer.wrap(reply, 16, 4).order(ByteOrder.LITTLE_ENDIAN).int
                check(responseLength in 20..reply.size - 20)
                check(ByteBuffer.wrap(reply, 20, 4).order(ByteOrder.LITTLE_ENDIAN).int == 0x05162463)
                check(reply.copyOfRange(24, 40).contentEquals(nonce))
            }
        }
        secret.fill(0)
    }

    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
    private fun little(value: Int) = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array()
    private fun ctr(key: ByteArray, iv: ByteArray) = Cipher.getInstance("AES/CTR/NoPadding").apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv)) }
}
