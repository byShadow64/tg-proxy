package io.github.byshadow64.tgproxy.core

import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock

enum class RegistryFailureCode { INVALID_ADDRESS, NOT_CONFIGURED, UNKNOWN_HELPER, DEVICE_NOT_REGISTERED, DEVICE_DENIED, RATE_LIMITED, UNVERIFIED_REGISTRY, REJECTED, TIMEOUT, CANCELLED }
class RegistryException(val code: RegistryFailureCode, internal val cooldownSeconds: Long? = null) : Exception(code.name)

/** An installation key, not a hardware identifier or an attestation. Private key never leaves its provider. */
interface RegistryDeviceIdentity {
    fun publicKeySpki(): ByteArray
    fun sign(message: ByteArray): ByteArray
}

fun interface RegistryTransport {
    fun post(path: String, body: ByteArray, cancelled: () -> Boolean): ByteArray
}

internal class RegistryHttpException(val status: Int, val safeError: String? = null, val retryAfterSeconds: Long? = null) : Exception("REGISTRY_HTTP_REJECTED")

/** Platform CA trust plus HTTPS identity; cancellation closes even a pending TCP/TLS socket. */
class HttpsRegistryTransport(
    baseUrl: String,
    private val factory: javax.net.ssl.SSLSocketFactory = javax.net.ssl.SSLContext.getDefault().socketFactory,
) : RegistryTransport {
    private val base = try {
        URI(baseUrl).also {
            require(it.scheme == "https" && !it.host.isNullOrBlank() && it.userInfo == null && it.query == null && it.fragment == null)
            require(it.port == -1 || it.port in 1..65535)
            require(it.rawPath.isNullOrEmpty() || it.rawPath == "/")
        }
    } catch (_: Exception) { throw RegistryException(RegistryFailureCode.NOT_CONFIGURED) }

    override fun post(path: String, body: ByteArray, cancelled: () -> Boolean): ByteArray {
        require(path in setOf("/v1/challenge", "/v1/register", "/v1/lease") && body.size in 1..8192)
        if (cancelled() || Thread.currentThread().isInterrupted) throw RegistryException(RegistryFailureCode.CANCELLED)
        val io = SessionIo(); val expired = AtomicBoolean(false)
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8)
        val watcher = Executors.newSingleThreadScheduledExecutor { task -> Thread(task, "tgproxy-registry-deadline").apply { isDaemon = true } }
        watcher.scheduleAtFixedRate({
            if (cancelled()) io.close()
            else if (System.nanoTime() >= deadline) { expired.set(true); io.close() }
            else io.expire(System.nanoTime())
        }, 0, 50, TimeUnit.MILLISECONDS)
        try {
            val host = base.host.removePrefix("[").removeSuffix("]"); val port = if (base.port == -1) 443 else base.port
            val address = BoundedDns.resolve(host, io)
            val raw = io.track(java.net.Socket())
            io.operation("registry-connect", 4_000, raw) { raw.connect(java.net.InetSocketAddress(address, port), 4_000) }
            val socket = io.track(factory.createSocket(raw, host, port, true), raw) as javax.net.ssl.SSLSocket
            socket.enabledProtocols = socket.supportedProtocols.filter { it == "TLSv1.2" || it == "TLSv1.3" }.toTypedArray()
            socket.sslParameters = socket.sslParameters.apply {
                endpointIdentificationAlgorithm = "HTTPS"
                serverNames = if (':' in host || host.all { it in "0123456789." }) emptyList() else listOf(javax.net.ssl.SNIHostName(host))
            }
            socket.soTimeout = 4_000
            io.operation("registry-tls", 4_000, socket) { socket.startHandshake() }
            val authority = (if (':' in host) "[$host]" else host) + (if (port == 443) "" else ":$port")
            val header = "POST $path HTTP/1.1\r\nHost: $authority\r\nContent-Type: application/json\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: ${body.size}\r\n\r\n".toByteArray(Charsets.US_ASCII)
            io.operation("registry-write", 4_000, socket) { socket.getOutputStream().apply { write(header); write(body); flush() } }
            val response = io.operation("registry-read", 4_000, socket) {
                val input = socket.getInputStream(); var headerBytes = 0
                fun line(): String {
                    val text = StringBuilder()
                    while (true) {
                        require(++headerBytes <= 8192)
                        val value = input.read(); require(value >= 0)
                        if (value == 13) { require(++headerBytes <= 8192 && input.read() == 10); return text.toString() }
                        require(value in 32..126 || value == 9); text.append(value.toChar())
                    }
                }
                val status = Regex("HTTP/1\\.[01] ([0-9]{3})(?: .*)?").matchEntire(line())?.groupValues?.get(1)?.toInt()
                    ?: throw RegistryException(RegistryFailureCode.UNVERIFIED_REGISTRY)
                val headers = mutableMapOf<String, String>()
                while (true) {
                    val item = line(); if (item.isEmpty()) break
                    require(item[0] != ' ' && item[0] != '\t' && ':' in item)
                    val name = item.substringBefore(':').lowercase(java.util.Locale.ROOT)
                    require(name.matches(Regex("[a-z0-9-]+")) && name !in headers && headers.size < 32)
                    headers[name] = item.substringAfter(':').trim()
                }
                val length = headers["content-length"]?.toIntOrNull()
                if (status != 200) {
                    val error = try {
                        if (length == null || length !in 1..16384 || "transfer-encoding" in headers) null else {
                            val envelope = RegistryJson.parse(input.exactly(length))
                            if (envelope.keys == setOf("v", "error") && envelope["v"] == 1L)
                                (envelope["error"] as? String)?.takeIf { it in setOf("not_found", "device_not_registered", "denied", "rate_limited") } else null
                        }
                    } catch (_: Exception) { null }
                    throw RegistryHttpException(status, error, headers["retry-after"]?.toLongOrNull()?.takeIf { it in 1..300 })
                }
                require("transfer-encoding" !in headers)
                require(headers["content-encoding"]?.lowercase(java.util.Locale.ROOT) in listOf(null, "identity"))
                require(length != null && length in 1..16384)
                input.exactly(length)
            }
            if (cancelled() || Thread.currentThread().isInterrupted) throw RegistryException(RegistryFailureCode.CANCELLED)
            if (expired.get()) throw RegistryException(RegistryFailureCode.TIMEOUT)
            return response
        } catch (e: RegistryHttpException) { throw e }
        catch (e: RegistryException) { throw e }
        catch (failure: Exception) {
            throw RegistryException(when {
                cancelled() || Thread.currentThread().isInterrupted -> RegistryFailureCode.CANCELLED
                expired.get() || failure is java.net.SocketTimeoutException -> RegistryFailureCode.TIMEOUT
                else -> RegistryFailureCode.UNVERIFIED_REGISTRY
            })
        } finally { io.close(); watcher.shutdownNow() }
    }
}

class RegisteredHelperLease(
    val ip: String, val port: Int, val fingerprintHex: String,
    val token: String, val issuedAt: Long, val expiresAt: Long,
    val helperId: String,
) {
    fun settings() = HelperSettings(ip, port, fingerprintHex, token)
    override fun toString() = "RegisteredHelperLease(<private>)"
}

/** Every lease issuance proves possession of this install's key; a data socket uses the short bearer lease. */
class HelperRegistryClient(
    private val transport: RegistryTransport,
    signingPublicKeySpki: ByteArray,
    private val identity: RegistryDeviceIdentity,
    private val monotonicNanos: () -> Long = { System.nanoTime() },
    private val clockSeconds: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    private val signingKey = try { RegistryCrypto.p256Key(signingPublicKeySpki) }
        catch (_: Exception) { throw RegistryException(RegistryFailureCode.NOT_CONFIGURED) }
    private val publicKey = try { identity.publicKeySpki().also { RegistryCrypto.p256Key(it) } }
        catch (_: Exception) { throw RegistryException(RegistryFailureCode.NOT_CONFIGURED) }
    private val device = MessageDigest.getInstance("SHA-256").digest(publicKey)
    private val deviceId = RegistryCrypto.hex(device)
    private val lock = ReentrantLock()
    private var registered = false
    private var cached: RegisteredHelperLease? = null
    private class Negative(val code: RegistryFailureCode, val untilNanos: Long)
    private val negatives = object : LinkedHashMap<String, Negative>(8, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Negative>?) = size > 8
    }
    private var serviceNegative: Negative? = null

    fun lease(input: String, forceRefresh: Boolean = false, cancelled: () -> Boolean = { false }): RegisteredHelperLease {
        val target = numericIp(input)
        try {
            while (!lock.tryLock(50, TimeUnit.MILLISECONDS)) checkCancelled(cancelled)
        } catch (_: InterruptedException) { Thread.currentThread().interrupt(); throw RegistryException(RegistryFailureCode.CANCELLED) }
        var negativeHit = false
        try {
            checkCancelled(cancelled)
            val now = clockSeconds()
            if (!forceRefresh) {
                cached?.let { if (it.ip == target && it.expiresAt - now >= 30 && now >= it.issuedAt - 30) return it }
                val negative = serviceNegative?.takeIf { it.untilNanos - monotonicNanos() > 0 }
                    ?: negatives[target]?.takeIf { it.untilNanos - monotonicNanos() > 0 }
                if (negative != null) { negativeHit = true; throw RegistryException(negative.code) }
            }
            if (!registered) register(cancelled)
            val response = try { prove("lease", target, cancelled) }
            catch (failure: RegistryException) {
                // Only the authenticated, explicit GC/missing-key code permits ONE enrollment retry.
                // Revocation (`denied`) and generic HTTP403 never enter this path.
                if (failure.code != RegistryFailureCode.DEVICE_NOT_REGISTERED) throw failure
                registered = false
                register(cancelled)
                prove("lease", target, cancelled)
            }
            val result = verifyLease(response, target)
            checkCancelled(cancelled)
            cached = result
            negatives.remove(target); serviceNegative = null
            return result
        } catch (e: RegistryException) {
            if (!negativeHit && e.code !in setOf(RegistryFailureCode.CANCELLED, RegistryFailureCode.INVALID_ADDRESS)) rememberFailure(target, e)
            throw e
        }
        catch (_: Exception) {
            val failure = RegistryException(RegistryFailureCode.UNVERIFIED_REGISTRY); rememberFailure(target, failure); throw failure
        }
        finally { lock.unlock() }
    }

    private fun rememberFailure(target: String, failure: RegistryException) {
        val seconds = if (failure.code in setOf(RegistryFailureCode.DEVICE_DENIED, RegistryFailureCode.RATE_LIMITED))
            maxOf(60, failure.cooldownSeconds ?: 60).coerceAtMost(300) else 15
        val negative = Negative(failure.code, monotonicNanos() + TimeUnit.SECONDS.toNanos(seconds))
        negatives[target] = negative
        if (failure.code != RegistryFailureCode.UNKNOWN_HELPER) serviceNegative = negative
    }

    private fun checkCancelled(cancelled: () -> Boolean) {
        if (cancelled() || Thread.currentThread().isInterrupted) throw RegistryException(RegistryFailureCode.CANCELLED)
    }

    private fun register(cancelled: () -> Boolean) {
        val response = RegistryJson.parse(prove("register", "", cancelled))
        require(response.keys == setOf("v", "device_id", "access") && response["v"] == 1L)
        require(response["device_id"] == deviceId && response["access"] == "registered-device-public")
        registered = true
    }

    private fun post(path: String, request: Map<String, Any>, cancelled: () -> Boolean, leaseRequest: Boolean): ByteArray {
        checkCancelled(cancelled)
        return try { transport.post(path, RegistryJson.canonical(request), cancelled) }
        catch (e: RegistryHttpException) {
            val code = when {
                leaseRequest && e.status == 404 && e.safeError == "not_found" -> RegistryFailureCode.UNKNOWN_HELPER
                e.status == 403 && e.safeError == "device_not_registered" -> RegistryFailureCode.DEVICE_NOT_REGISTERED
                e.status == 403 && e.safeError == "denied" -> RegistryFailureCode.DEVICE_DENIED
                e.status == 429 -> RegistryFailureCode.RATE_LIMITED
                else -> RegistryFailureCode.REJECTED
            }
            throw RegistryException(code, if (code == RegistryFailureCode.RATE_LIMITED) e.retryAfterSeconds else null)
        }
    }

    private fun prove(purpose: String, target: String, cancelled: () -> Boolean): ByteArray {
        val challenge = RegistryJson.parse(post("/v1/challenge", mapOf("v" to 1L, "public_key" to RegistryCrypto.encode(publicKey), "purpose" to purpose, "target" to target), cancelled, purpose == "lease"))
        require(challenge.keys == setOf("v", "challenge", "expires_at") && challenge["v"] == 1L)
        val nonce = challenge["challenge"] as String
        RegistryCrypto.decode(nonce, 32)
        val now = clockSeconds()
        val expires = challenge["expires_at"] as Long
        // A 60-second server challenge can appear 61 seconds ahead even with subsecond
        // clock skew. Match the descriptor/lease allowance, without accepting stale
        // challenges or extending the server's authoritative nonce deadline.
        require(now >= 0 && expires > now && expires - now <= CHALLENGE_TTL_SECONDS + CLOCK_SKEW_SECONDS)
        val proof = RegistryJson.canonical(mapOf("v" to 1L, "device_id" to deviceId, "purpose" to purpose, "target" to target, "challenge" to nonce))
        checkCancelled(cancelled)
        val signature = identity.sign(DEVICE_CONTEXT + proof)
        RegistryCrypto.requireDer(signature)
        checkCancelled(cancelled)
        return post("/v1/$purpose", mapOf("v" to 1L, "public_key" to RegistryCrypto.encode(publicKey), "purpose" to purpose,
            "target" to target, "challenge" to nonce, "signature" to RegistryCrypto.encode(signature)), cancelled, purpose == "lease")
    }

    internal fun verifyLease(bytes: ByteArray, target: String): RegisteredHelperLease {
        val outer = RegistryJson.parse(bytes)
        require(outer.keys == setOf("v", "descriptor", "token") && outer["v"] == 1L)
        @Suppress("UNCHECKED_CAST") val descriptor = outer["descriptor"] as Map<String, Any>
        require(descriptor.keys == setOf("v", "payload", "signature") && descriptor["v"] == 1L)
        val payload = RegistryCrypto.decode(descriptor["payload"] as String, maximum = 2048)
        RegistryCrypto.verify(signingKey, DESCRIPTOR_CONTEXT + payload, RegistryCrypto.decode(descriptor["signature"] as String, maximum = 72))
        val data = RegistryJson.parse(payload)
        require(RegistryJson.canonical(data).contentEquals(payload))
        require(data.keys == setOf("v", "helper_id", "ip", "port", "fingerprint", "iat", "exp", "protocol", "access") && data["v"] == 1L)
        require(data["protocol"] == "helper-v2-lease" && data["access"] == "registered-device-public")
        val ip = data["ip"] as String; require(ip == target && numericIp(ip) == ip)
        val port = data["port"] as Long; require(port in 1..65535)
        val pin = data["fingerprint"] as String; require(pin.matches(Regex("[0-9a-f]{64}")))
        val helperId = RegistryCrypto.decode(data["helper_id"] as String, 16)
        val iat = data["iat"] as Long; val exp = data["exp"] as Long; val now = clockSeconds()
        require(iat >= 0 && iat <= now + 30 && iat >= now - 600 && exp > iat && exp - iat <= 600 && exp - now >= 30)
        val token = outer["token"] as String
        require(token.length in 1..512 && token.all { it.code in 33..126 })
        val pieces = token.split('.'); require(pieces.size == 3 && pieces[0] == "TGL1")
        val binary = RegistryCrypto.decode(pieces[1], 113)
        RegistryCrypto.verify(signingKey, LEASE_CONTEXT + binary, RegistryCrypto.decode(pieces[2], maximum = 72))
        val buffer = ByteBuffer.wrap(binary)
        require(buffer.get().toInt() == 1)
        val tokenHelper = ByteArray(16).also(buffer::get); val tokenDevice = ByteArray(32).also(buffer::get); val certificate = ByteArray(32).also(buffer::get)
        val tokenIat = buffer.long; val tokenExp = buffer.long
        require(MessageDigest.isEqual(tokenHelper, helperId) && MessageDigest.isEqual(tokenDevice, device) && RegistryCrypto.hex(certificate) == pin)
        require(tokenIat >= iat && tokenIat <= now + 30 && tokenIat >= now - 600 && tokenExp > tokenIat && tokenExp - tokenIat <= 600 && tokenExp <= exp && tokenExp - now >= 30)
        return RegisteredHelperLease(ip, port.toInt(), pin, token, tokenIat, tokenExp, RegistryCrypto.encode(helperId))
    }

    companion object {
        private const val CHALLENGE_TTL_SECONDS = 60L
        private const val CLOCK_SKEW_SECONDS = 30L
        internal val DEVICE_CONTEXT = "TGPROXY_REGISTRY_DEVICE_V1\u0000".toByteArray(Charsets.US_ASCII)
        internal val DESCRIPTOR_CONTEXT = "TGPROXY_REGISTRY_DESCRIPTOR_V1\u0000".toByteArray(Charsets.US_ASCII)
        internal val LEASE_CONTEXT = "TGPROXY_REGISTRY_LEASE_V1\u0000".toByteArray(Charsets.US_ASCII)

        /** Reject hostnames, URLs, ports, scopes and shorthand before any DNS/network call. */
        fun numericIp(input: String): String {
            try {
                val value = input.trim(); require(value.length in 1..45)
                if (':' !in value) {
                    val parts = value.split('.')
                    require(parts.size == 4 && parts.all { it.length in 1..3 && it.all { c -> c in '0'..'9' } && (it.length == 1 || !it.startsWith('0')) && it.toInt() in 0..255 })
                    require(parts.any { it.toInt() != 0 } && parts[0].toInt() !in 224..239)
                    return parts.joinToString(".") { it.toInt().toString() }
                }
                require(value.all { it in "0123456789abcdefABCDEF:" })
                val halves = value.split("::"); require(halves.size in 1..2)
                fun side(text: String): List<Int> = if (text.isEmpty()) emptyList() else text.split(':').map {
                    require(it.length in 1..4); it.toInt(16)
                }
                val left = side(halves[0]); val right = if (halves.size == 2) side(halves[1]) else emptyList()
                require(if (halves.size == 1) left.size == 8 else left.size + right.size < 8)
                val words = (left + List(8 - left.size - right.size) { 0 } + right).toIntArray()
                require(words.any { it != 0 } && (words[0] and 0xff00) != 0xff00)
                var best = -1; var length = 1; var index = 0
                while (index < 8) {
                    if (words[index] != 0) { index++; continue }
                    val start = index; while (index < 8 && words[index] == 0) index++
                    if (index - start > length) { best = start; length = index - start }
                }
                if (best < 0) return words.joinToString(":") { it.toString(16) }
                return words.take(best).joinToString(":") { it.toString(16) } + "::" + words.drop(best + length).joinToString(":") { it.toString(16) }
            } catch (_: Exception) { throw RegistryException(RegistryFailureCode.INVALID_ADDRESS) }
        }
    }
}

internal object RegistryCrypto {
    fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    fun decode(value: String, size: Int? = null, maximum: Int = 4096): ByteArray {
        require(value.isNotEmpty() && value.length <= maximum * 2 && value.all { it in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" })
        val bytes = Base64.getUrlDecoder().decode(value)
        require(bytes.size <= maximum && (size == null || bytes.size == size) && encode(bytes) == value)
        return bytes
    }
    fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
    private val curve: ECParameterSpec by lazy { AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java) }
    fun p256Key(bytes: ByteArray): ECPublicKey {
        require(bytes.size in 64..256)
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(bytes)) as ECPublicKey
        require(key.encoded.contentEquals(bytes) && key.params.order == curve.order && key.params.generator == curve.generator && key.params.curve == curve.curve && key.params.cofactor == curve.cofactor)
        return key
    }
    fun requireDer(bytes: ByteArray) {
        require(bytes.size in 8..72 && bytes[0].toInt() == 48 && bytes[1].toInt() == bytes.size - 2)
        var offset = 2
        repeat(2) {
            require(offset + 2 <= bytes.size && bytes[offset++].toInt() == 2)
            val length = bytes[offset++].toInt(); require(length in 1..33 && offset + length <= bytes.size)
            require(bytes[offset].toInt() and 128 == 0)
            require(length == 1 || bytes[offset] != 0.toByte() || bytes[offset + 1].toInt() and 128 != 0)
            val value = java.math.BigInteger(1, bytes.copyOfRange(offset, offset + length)); require(value.signum() > 0 && value < curve.order)
            offset += length
        }
        require(offset == bytes.size)
    }
    fun verify(key: ECPublicKey, message: ByteArray, signature: ByteArray) {
        requireDer(signature)
        require(Signature.getInstance("SHA256withECDSA").run { initVerify(key); update(message); verify(signature) })
    }
}

/** Small strict JSON subset: objects, strings and unsigned integral numbers, with bounded nesting. */
internal object RegistryJson {
    fun canonical(data: Map<String, Any>): ByteArray {
        fun quote(value: String): String = buildString {
            append('"')
            for (c in value) when (c) {
                '"' -> append("\\\""); '\\' -> append("\\\\")
                else -> if (c.code < 32 || c.code > 126) append("\\u%04x".format(c.code)) else append(c)
            }
            append('"')
        }
        fun objectText(value: Map<String, Any>): String = value.toSortedMap().entries.joinToString(",", "{", "}") { (key, item) ->
            val encoded = when (item) {
                is String -> quote(item)
                is Long -> { require(item >= 0); item.toString() }
                is Int -> { require(item >= 0); item.toString() }
                is Map<*, *> -> { @Suppress("UNCHECKED_CAST") objectText(item as Map<String, Any>) }
                else -> error("REGISTRY_INVALID_JSON")
            }
            quote(key) + ":" + encoded
        }
        return objectText(data).toByteArray(Charsets.US_ASCII)
    }
    fun parse(bytes: ByteArray): Map<String, Any> {
        require(bytes.size in 1..16384)
        val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        var i = 0
        fun white() { while (i < text.length && text[i] in " \r\n\t") i++ }
        fun char(c: Char) { white(); require(i < text.length && text[i++] == c) }
        fun string(): String {
            char('"'); val out = StringBuilder()
            while (i < text.length) {
                val c = text[i++]; if (c == '"') return out.toString()
                require(c.code >= 32)
                if (c != '\\') { out.append(c); continue }
                require(i < text.length)
                when (val e = text[i++]) {
                    '"', '\\', '/' -> out.append(e)
                    'b' -> out.append('\b'); 'f' -> out.append('\u000c'); 'n' -> out.append('\n'); 'r' -> out.append('\r'); 't' -> out.append('\t')
                    'u' -> { require(i + 4 <= text.length && text.substring(i, i + 4).all { it in "0123456789abcdefABCDEF" }); out.append(text.substring(i, i + 4).toInt(16).toChar()); i += 4 }
                    else -> error("REGISTRY_INVALID_JSON")
                }
            }
            error("REGISTRY_INVALID_JSON")
        }
        fun obj(depth: Int): Map<String, Any> {
            require(depth <= 3); char('{'); val out = linkedMapOf<String, Any>(); white()
            if (i < text.length && text[i] == '}') { i++; return out }
            while (true) {
                require(out.size < 16); val key = string(); require(key !in out); char(':'); white()
                val value: Any = when {
                    i < text.length && text[i] == '"' -> string()
                    i < text.length && text[i] == '{' -> obj(depth + 1)
                    else -> {
                        val start = i; while (i < text.length && text[i] in '0'..'9') i++
                        require(i > start && (i - start == 1 || text[start] != '0')); text.substring(start, i).toLong()
                    }
                }
                out[key] = value; white(); require(i < text.length)
                if (text[i] == '}') { i++; return out }
                char(',')
            }
        }
        val result = obj(0); white(); require(i == text.length); return result
    }
}
