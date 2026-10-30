package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class HelperRegistryClientTest {
    private val ip = "192.0.2.10"
    private fun pair() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private class Identity : RegistryDeviceIdentity {
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        var proofs = 0
        override fun publicKeySpki() = key.public.encoded
        override fun sign(message: ByteArray): ByteArray { proofs++; return Signature.getInstance("SHA256withECDSA").run { initSign(key.private); update(message); sign() } }
    }
    private inner class Registry : RegistryTransport {
        val signer = pair(); val identity = Identity(); var now = 1_900_000_000L
        val device = MessageDigest.getInstance("SHA-256").digest(identity.publicKeySpki())
        val helper = ByteArray(16) { 17 }; val pin = ByteArray(32) { 34 }
        private var challenge = 0
        private val pending = mutableMapOf<String, Pair<String, String>>()
        val paths = mutableListOf<String>(); val requests = mutableListOf<ByteArray>()
        fun client() = HelperRegistryClient(this, signer.public.encoded, identity) { now }
        fun response(changes: Map<String, Any> = emptyMap(), tokenChange: (ByteArray) -> Unit = {}): Map<String, Any> {
            val data = mapOf("v" to 1L, "helper_id" to RegistryCrypto.encode(helper), "ip" to ip, "port" to 8444L,
                "fingerprint" to RegistryCrypto.hex(pin), "iat" to now, "exp" to now + 600, "protocol" to "helper-v2-lease", "access" to "registered-device-public") + changes
            val payload = RegistryJson.canonical(data)
            val binary = ByteBuffer.allocate(113).put(1).put(helper).put(device).put(pin).putLong(now).putLong(now + 600).put(ByteArray(16) { challenge.toByte() }).array().also(tokenChange)
            return mapOf("v" to 1L, "descriptor" to descriptor(payload), "token" to "TGL1.${RegistryCrypto.encode(binary)}.${RegistryCrypto.encode(sign(HelperRegistryClient.LEASE_CONTEXT + binary))}")
        }
        fun descriptor(payload: ByteArray): Map<String, Any> = mapOf("v" to 1L, "payload" to RegistryCrypto.encode(payload), "signature" to RegistryCrypto.encode(sign(HelperRegistryClient.DESCRIPTOR_CONTEXT + payload)))
        private fun sign(bytes: ByteArray) = Signature.getInstance("SHA256withECDSA").run { initSign(signer.private); update(bytes); sign() }
        override fun post(path: String, body: ByteArray, cancelled: () -> Boolean): ByteArray {
            assertFalse(cancelled()); paths.add(path); requests.add(body.copyOf())
            val data = RegistryJson.parse(body)
            assertEquals(1L, data["v"]); assertEquals(RegistryCrypto.encode(identity.publicKeySpki()), data["public_key"])
            val purpose = data["purpose"] as String; val target = data["target"] as String
            if (path == "/v1/challenge") {
                assertEquals(setOf("v", "public_key", "purpose", "target"), data.keys)
                val nonce = RegistryCrypto.encode(ByteArray(32) { (challenge + it).toByte() }); challenge++
                pending[nonce] = purpose to target
                return RegistryJson.canonical(mapOf("v" to 1L, "challenge" to nonce, "expires_at" to now + 60))
            }
            assertEquals(setOf("v", "public_key", "purpose", "target", "challenge", "signature"), data.keys)
            assertEquals(purpose to target, pending.remove(data["challenge"] as String))
            val proof = RegistryJson.canonical(mapOf("v" to 1L, "device_id" to RegistryCrypto.hex(device), "purpose" to purpose, "target" to target, "challenge" to data["challenge"]!!))
            RegistryCrypto.verify(RegistryCrypto.p256Key(identity.publicKeySpki()), HelperRegistryClient.DEVICE_CONTEXT + proof, RegistryCrypto.decode(data["signature"] as String, maximum = 72))
            return if (path == "/v1/register") {
                assertEquals("register", purpose); assertEquals("", target)
                RegistryJson.canonical(mapOf("v" to 1L, "device_id" to RegistryCrypto.hex(device), "access" to "registered-device-public"))
            } else {
                assertEquals("/v1/lease", path); assertEquals("lease", purpose); assertEquals(ip, target)
                RegistryJson.canonical(response())
            }
        }
    }
    private fun rejects(block: () -> Unit) { try { block(); fail("Expected rejection") } catch (e: AssertionError) { throw e } catch (_: Exception) {} }

    @Test fun independentPythonDescriptorLeaseAndDeviceProofVector() {
        val vector = javaClass.getResourceAsStream("/helper_registry_v1.json")!!.use { RegistryJson.parse(it.readBytes()) }
        val publicKey = RegistryCrypto.decode(vector["device_public_key"] as String)
        val identity = object : RegistryDeviceIdentity {
            override fun publicKeySpki() = publicKey
            override fun sign(message: ByteArray): ByteArray = error("This vector verification must not sign")
        }
        val client = HelperRegistryClient(RegistryTransport { _, _, _ -> error("No network in vector test") }, RegistryCrypto.decode(vector["registry_public_key"] as String), identity) { 1000L }
        val reply = RegistryJson.canonical(mapOf("v" to 1L, "descriptor" to vector["descriptor"]!!, "token" to vector["lease"]!!))
        val result = client.verifyLease(reply, ip)
        assertEquals(ip, result.ip); assertEquals(8444, result.port); assertEquals(1600L, result.expiresAt)
        @Suppress("UNCHECKED_CAST") val proof = vector["device_proof"] as Map<String, Any>
        val canonical = RegistryJson.canonical(mapOf("v" to 1L, "device_id" to vector["device_id"]!!, "purpose" to proof["purpose"]!!, "target" to proof["target"]!!, "challenge" to proof["challenge"]!!))
        RegistryCrypto.verify(RegistryCrypto.p256Key(publicKey), HelperRegistryClient.DEVICE_CONTEXT + canonical, RegistryCrypto.decode(proof["signature"] as String, maximum = 72))
        assertFalse(result.toString().contains(result.token)); assertFalse(result.settings().toString().contains(result.token))
    }

    @Test fun registersInstallationAndProvesEveryRefreshWithNoStaticLeaseInRequests() {
        val registry = Registry(); val client = registry.client()
        val first = client.lease(ip); assertEquals(2, registry.identity.proofs)
        assertSame(first, client.lease(ip)); assertEquals(4, registry.paths.size)
        registry.now += 570; assertSame(first, client.lease(ip))
        registry.now++; val refreshed = client.lease(ip)
        assertNotEquals(first.token, refreshed.token); assertEquals(3, registry.identity.proofs)
        assertEquals(1, registry.paths.count { it == "/v1/register" }); assertEquals(2, registry.paths.count { it == "/v1/lease" })
        for (body in registry.requests) assertFalse(String(body).contains(first.token))
    }

    @Test fun challengeAllowsBoundedServerClockSkewAndStillVerifiesSignedLease() {
        for (serverAhead in listOf(0L, 1L, 30L)) {
            val registry = Registry()
            val client = HelperRegistryClient(registry, registry.signer.public.encoded, registry.identity) { registry.now - serverAhead }
            val lease = client.lease(ip)
            assertEquals(ip, lease.ip)
            assertEquals(registry.now, lease.issuedAt)
            assertEquals("One proof per register/lease, with no retries for clock rounding", 2, registry.identity.proofs)
            assertEquals(listOf("/v1/challenge", "/v1/register", "/v1/challenge", "/v1/lease"), registry.paths)
        }
    }

    @Test fun staleExcessiveAndOverflowingChallengeExpiryFailBeforeSigning() {
        for (expiry in listOf(1_899_999_999L, 1_900_000_000L, 1_900_000_091L, Long.MAX_VALUE)) {
            val registry = Registry()
            val transport = RegistryTransport { path, body, cancelled ->
                val original = RegistryJson.parse(registry.post(path, body, cancelled))
                assertEquals("/v1/challenge", path)
                RegistryJson.canonical(original + ("expires_at" to expiry))
            }
            val client = HelperRegistryClient(transport, registry.signer.public.encoded, registry.identity) { registry.now }
            try { client.lease(ip); fail("Challenge expiry must be strictly future and at most 90 seconds ahead") }
            catch (e: RegistryException) { assertEquals(RegistryFailureCode.UNVERIFIED_REGISTRY, e.code) }
            assertEquals(0, registry.identity.proofs)
            assertEquals(listOf("/v1/challenge"), registry.paths)
        }
    }

    @Test fun cancellationAfterSkewedChallengeNeverSignsOrSubmitsProof() {
        val registry = Registry()
        val cancelled = AtomicBoolean()
        val transport = RegistryTransport { path, body, cancel ->
            registry.post(path, body, cancel).also { cancelled.set(true) }
        }
        val client = HelperRegistryClient(transport, registry.signer.public.encoded, registry.identity) { registry.now - 1 }
        try { client.lease(ip) { cancelled.get() }; fail() }
        catch (e: RegistryException) { assertEquals(RegistryFailureCode.CANCELLED, e.code) }
        assertEquals(0, registry.identity.proofs)
        assertEquals(listOf("/v1/challenge"), registry.paths)
    }

    @Test fun signedButInvalidDescriptorOrMismatchedBearerBindingsFailClosed() {
        val registry = Registry(); val client = registry.client()
        for (change in listOf(mapOf("ip" to "192.0.2.11"), mapOf("port" to 65536L), mapOf("fingerprint" to "AA".repeat(32)),
            mapOf("exp" to registry.now + 601), mapOf("iat" to registry.now + 31), mapOf("exp" to registry.now + 20),
            mapOf("protocol" to "legacy"), mapOf("access" to "private"), mapOf("helper_id" to RegistryCrypto.encode(ByteArray(15))), mapOf("extra" to 1L))) {
            rejects { client.verifyLease(RegistryJson.canonical(registry.response(change)), ip) }
        }
        for (offset in listOf(1, 17, 49, 81, 89)) {
            rejects { client.verifyLease(RegistryJson.canonical(registry.response(tokenChange = { it[offset] = (it[offset].toInt() xor 1).toByte() })), ip) }
        }
        val otherDevice = Identity()
        val other = HelperRegistryClient(registry, registry.signer.public.encoded, otherDevice) { registry.now }
        rejects { other.verifyLease(RegistryJson.canonical(registry.response()), ip) }
    }

    @Test fun alteredUncanonicalPayloadsAndSignaturesAreRejected() {
        val registry = Registry(); val client = registry.client(); val response = registry.response()
        @Suppress("UNCHECKED_CAST") val descriptor = response["descriptor"] as Map<String, Any>
        val payload = RegistryCrypto.decode(descriptor["payload"] as String)
        val changed = payload.copyOf().also { it[5] = (it[5].toInt() xor 1).toByte() }
        rejects { client.verifyLease(RegistryJson.canonical(response + ("descriptor" to (descriptor + ("payload" to RegistryCrypto.encode(changed))))), ip) }
        val spaced = String(payload).replace(",", ", ").toByteArray()
        rejects { client.verifyLease(RegistryJson.canonical(response + ("descriptor" to registry.descriptor(spaced))), ip) }
        rejects { client.verifyLease(RegistryJson.canonical(response + ("token" to (response["token"] as String) + "=")), ip) }
        val wrong = HelperRegistryClient(registry, pair().public.encoded, registry.identity) { registry.now }
        rejects { wrong.verifyLease(RegistryJson.canonical(response), ip) }
    }

    @Test fun numericOnlyCanonicalAddressesAndStrictBoundedJsonDerSpki() {
        assertEquals("2001:db8::1", HelperRegistryClient.numericIp("2001:0DB8:0:0:0:0:0:1"))
        assertEquals("::ffff:c000:201", HelperRegistryClient.numericIp("::ffff:c000:201"))
        for (bad in listOf("host.example", "127.1", "0127.0.0.1", "127.0.0.1:8444", "[::1]", "::1%wlan0", "https://192.0.2.10", "1::2::3", "256.0.0.1", "::", "0.0.0.0", "224.0.0.1", "239.255.255.255", "ff02::1")) {
            try { HelperRegistryClient.numericIp(bad); fail(bad) } catch (e: RegistryException) { assertEquals(RegistryFailureCode.INVALID_ADDRESS, e.code) }
        }
        for (text in listOf("{\"v\":1,\"v\":1}", "{\"v\":1,\"\\u0076\":1}", "{\"v\":01}", "{\"v\":1.0}", "{\"v\":true}", "{\"v\":null}", "{\"v\":[]}", "{\"v\":1} trailing", "{\"v\":{\"a\":{\"b\":{\"c\":{}}}}}")) rejects { RegistryJson.parse(text.toByteArray()) }
        rejects { RegistryJson.parse(ByteArray(16385)) }; rejects { RegistryCrypto.p256Key(pair().public.encoded + 0) }
        val identity = Identity(); val sig = identity.sign(byteArrayOf(1))
        RegistryCrypto.requireDer(sig); rejects { RegistryCrypto.requireDer(sig + 0) }; rejects { RegistryCrypto.requireDer(sig.copyOf().also { it[1] = 0x80.toByte() }) }
        for (bad in listOf("Zg=", "Zh", "Z g", "+/")) rejects { RegistryCrypto.decode(bad) }
    }

    @Test fun cancelledEnrollmentDoesNotSignOrRequestAnythingAndUnknownHelperIsSafeCode() {
        val registry = Registry(); val client = registry.client()
        try { client.lease(ip) { true }; fail() } catch (e: RegistryException) { assertEquals(RegistryFailureCode.CANCELLED, e.code) }
        assertTrue(registry.requests.isEmpty()); assertEquals(0, registry.identity.proofs)
        val missing = HelperRegistryClient(RegistryTransport { path, body, cancel ->
            if (path == "/v1/lease") throw RegistryHttpException(404, "not_found") else registry.post(path, body, cancel)
        }, registry.signer.public.encoded, registry.identity) { registry.now }
        try { missing.lease(ip); fail() } catch (e: RegistryException) {
            assertEquals(RegistryFailureCode.UNKNOWN_HELPER, e.code)
            assertFalse(e.toString().contains(ip)); assertFalse(e.toString().contains(RegistryCrypto.hex(registry.device)))
        }
    }

    @Test fun ipv6CanonicalDescriptorAndDeniedRateLimitedResponsesAreBounded() {
        val registry = Registry(); val client = registry.client()
        val canonical = "2001:db8::1"
        assertEquals(canonical, HelperRegistryClient.numericIp("2001:0DB8:0000:0:0:0:0:1"))
        assertEquals(canonical, client.verifyLease(RegistryJson.canonical(registry.response(mapOf("ip" to canonical))), canonical).ip)
        rejects { client.verifyLease(RegistryJson.canonical(registry.response(mapOf("ip" to "2001:0db8::1"))), canonical) }
        assertEquals("2001:db8::1:0:0:1", HelperRegistryClient.numericIp("2001:db8:0:0:1:0:0:1"))
        for ((status, wire, expected) in listOf(Triple(403, "denied", RegistryFailureCode.DEVICE_DENIED), Triple(404, null, RegistryFailureCode.REJECTED), Triple(429, "rate_limited", RegistryFailureCode.RATE_LIMITED), Triple(429, null, RegistryFailureCode.RATE_LIMITED))) {
            val server = Registry()
            val subject = HelperRegistryClient(RegistryTransport { path, body, cancel ->
                if (path == "/v1/lease") throw RegistryHttpException(status, wire, 60) else server.post(path, body, cancel)
            }, server.signer.public.encoded, server.identity) { server.now }
            try { subject.lease(ip); fail() } catch (e: RegistryException) { assertEquals(expected, e.code) }
            val count = server.paths.size
            try { subject.lease(ip); fail() } catch (e: RegistryException) { assertEquals(expected, e.code) }
            assertEquals(1, server.paths.count { it == "/v1/register" }) // Never silently re-register a denied key.
            if (status == 429) assertEquals(count, server.paths.size)
            if (status == 403) {
                try { subject.lease(ip, forceRefresh = true); fail() } catch (e: RegistryException) { assertEquals(RegistryFailureCode.DEVICE_DENIED, e.code) }
                assertEquals(1, server.paths.count { it == "/v1/register" })
            }
        }
    }

    @Test fun negativeServiceCacheStopsConnectionStormUsesMonotonicClockAndExplicitRetryOnly() {
        val identity = Identity(); var requests = 0; var monotonic = 0L; var wall = 1_900_000_000L
        val client = HelperRegistryClient(RegistryTransport { _, _, _ -> requests++; throw RegistryException(RegistryFailureCode.TIMEOUT) },
            pair().public.encoded, identity, monotonicNanos = { monotonic }, clockSeconds = { wall })
        repeat(32) { try { client.lease(ip); fail() } catch (e: RegistryException) { assertEquals(RegistryFailureCode.TIMEOUT, e.code) } }
        assertEquals(1, requests)
        wall += 100_000 // A wall-clock change cannot expire a failure cooldown.
        try { client.lease("192.0.2.11"); fail() } catch (_: RegistryException) {}
        assertEquals(1, requests)
        monotonic = TimeUnit.SECONDS.toNanos(14)
        try { client.lease(ip); fail() } catch (_: RegistryException) {}
        assertEquals(1, requests)
        monotonic = TimeUnit.SECONDS.toNanos(15)
        try { client.lease(ip); fail() } catch (_: RegistryException) {}
        assertEquals(2, requests)
        try { client.lease(ip, forceRefresh = true); fail() } catch (_: RegistryException) {}
        assertEquals(3, requests)
        assertEquals(0, identity.proofs) // No reused or fabricated challenge, no background retry.
    }

    @Test fun garbageCollectedRegistrationUsesSameKeyAndRetriesEnrollmentOnlyOnce() {
        val registry = Registry(); var missing = false; var alwaysMissing = false
        val transport = RegistryTransport { path, body, cancel ->
            if (path == "/v1/challenge" && RegistryJson.parse(body)["purpose"] == "lease" && (missing || alwaysMissing)) {
                missing = false; throw RegistryHttpException(403, "device_not_registered")
            }
            registry.post(path, body, cancel)
        }
        val client = HelperRegistryClient(transport, registry.signer.public.encoded, registry.identity) { registry.now }
        client.lease(ip); registry.now += 901; missing = true
        client.lease(ip)
        assertEquals(2, registry.paths.count { it == "/v1/register" })
        for (request in registry.requests) assertEquals(RegistryCrypto.encode(registry.identity.publicKeySpki()), RegistryJson.parse(request)["public_key"])
        registry.now += 901; alwaysMissing = true
        val before = registry.paths.count { it == "/v1/register" }
        try { client.lease(ip); fail() } catch (e: RegistryException) { assertEquals(RegistryFailureCode.DEVICE_NOT_REGISTERED, e.code) }
        assertEquals(before + 1, registry.paths.count { it == "/v1/register" })
    }

    @Test fun localTrustedTlsWorksAndUntrustedCertificateSendsNoApplicationBytes() {
        TlsFixture.server { socket ->
            val input = socket.getInputStream(); val header = StringBuilder()
            while (!header.endsWith("\r\n\r\n")) header.append(input.read().also { require(it >= 0) }.toChar())
            val length = Regex("Content-Length: ([0-9]+)").find(header)!!.groupValues[1].toInt()
            input.exactly(length)
            socket.getOutputStream().apply { write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}".toByteArray()); flush() }
        }.use { server ->
            val transport = HttpsRegistryTransport("https://127.0.0.1:${server.port}", TlsFixture.clientFactory)
            assertArrayEquals("{}".toByteArray(), transport.post("/v1/challenge", "{\"v\":1}".toByteArray()) { false })
            server.assertSuccess()
        }
        val leaked = AtomicBoolean(false)
        TlsFixture.server { socket -> try { if (socket.getInputStream().read() >= 0) leaked.set(true) } catch (_: Exception) {} }.use { server ->
            try { HttpsRegistryTransport("https://127.0.0.1:${server.port}").post("/v1/challenge", "{\"v\":1}".toByteArray()) { false }; fail() }
            catch (e: RegistryException) { assertEquals(RegistryFailureCode.UNVERIFIED_REGISTRY, e.code) }
            server.assertSuccess(); assertFalse(leaked.get())
        }
    }

    @Test fun cancellationClosesPendingTlsWithoutWaitingForNetworkTimeout() {
        val accepted = CountDownLatch(1); val cancel = AtomicBoolean(); val failure = AtomicReference<Throwable?>()
        LocalServer { socket -> accepted.countDown(); try { while (socket.getInputStream().read() >= 0) {} } catch (_: Exception) {} }.use { server ->
            val worker = Thread {
                try { HttpsRegistryTransport("https://127.0.0.1:${server.port}").post("/v1/challenge", "{\"v\":1}".toByteArray()) { cancel.get() } }
                catch (e: Throwable) { failure.set(e) }
            }
            worker.start(); assertTrue(accepted.await(2, TimeUnit.SECONDS)); cancel.set(true); worker.join(2_000)
            assertFalse(worker.isAlive); assertEquals(RegistryFailureCode.CANCELLED, (failure.get() as RegistryException).code)
            server.assertSuccess()
        }
    }
}
