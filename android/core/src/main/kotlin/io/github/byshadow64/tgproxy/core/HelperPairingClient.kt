package io.github.byshadow64.tgproxy.core

import java.io.DataOutputStream
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

enum class PairingFailureCode { INVALID_ADDRESS, INVALID_CODE, CANCELLED, TIMEOUT, UNVERIFIED_SERVER }
class PairingException(val code: PairingFailureCode) : Exception(code.name)
class PairingEndpoint(val host: String, val port: Int) { override fun toString() = "PairingEndpoint(<private>)" }
class PairedHelper(val host: String, val port: Int, val fingerprintHex: String, val token: String) {
    override fun toString() = "PairedHelper(<private>)"
}

/**
 * Enrollment authenticates the certificate using a 128-bit owner code delivered over SSH.
 * The code and bearer token are NEVER sent by the client. A different TLS certificate
 * changes both proofs, preventing a TLS-intercepting peer from forwarding enrollment.
 * Normal Helper sessions still require the persisted certificate pin before any token.
 */
object HelperPairingClient {
    internal val clientContext = "TGPROXY_PAIR_CLIENT_V1\u0000".toByteArray(Charsets.US_ASCII)
    internal val serverContext = "TGPROXY_PAIR_SERVER_V1\u0000".toByteArray(Charsets.US_ASCII)
    private val random = SecureRandom()

    fun endpoint(input: String, defaultPort: Int = 8444): PairingEndpoint {
        try {
            require(input.length <= 128)
            var host = input.trim(); var port = defaultPort
            if (host.startsWith('[')) {
                val end = host.indexOf(']'); require(end > 0)
                val suffix = host.substring(end + 1)
                if (suffix.isNotEmpty()) { require(suffix.startsWith(':')); port = suffix.substring(1).toInt() }
                host = host.substring(1, end)
            } else if (host.count { it == ':' } == 1 && '.' in host) {
                val split = host.lastIndexOf(':'); port = host.substring(split + 1).toInt(); host = host.substring(0, split)
            }
            require(port in 1..65535 && host.isNotEmpty() && host.all { it in "0123456789abcdefABCDEF:." })
            val numeric = if (':' in host) InetAddress.getByName(host) else BoundedDns.ipv4Literal(host)
            require(numeric != null)
            return PairingEndpoint(numeric.hostAddress!!, port)
        } catch (_: Exception) { throw PairingException(PairingFailureCode.INVALID_ADDRESS) }
    }

    internal fun parseCode(input: String): Pair<String, ByteArray> {
        val code = input.trim()
        val match = Regex("TG1\\.([A-Za-z0-9_-]{11})\\.([A-Za-z0-9_-]{22})").matchEntire(code)
            ?: throw PairingException(PairingFailureCode.INVALID_CODE)
        try {
            decode(match.groupValues[1], 8); decode(match.groupValues[2], 16)
        } catch (_: Exception) { throw PairingException(PairingFailureCode.INVALID_CODE) }
        return match.groupValues[1] to MessageDigest.getInstance("SHA-256").digest(code.toByteArray(Charsets.US_ASCII))
    }
    internal fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    internal fun decode(value: String, size: Int? = null, maximum: Int = 4096): ByteArray {
        require(value.isNotEmpty() && value.length <= maximum * 2 && value.all { it in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" })
        val bytes = Base64.getUrlDecoder().decode(value)
        require(bytes.size <= maximum && (size == null || bytes.size == size) && encode(bytes) == value)
        return bytes
    }
    internal fun hmac(key: ByteArray, vararg parts: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key, "HmacSHA256")); parts.forEach { update(it) }; doFinal()
    }
    internal fun clientProof(key: ByteArray, id: String, nonce: ByteArray, cert: ByteArray) =
        hmac(key, clientContext, id.toByteArray(Charsets.US_ASCII), byteArrayOf(0), nonce, cert)
    internal fun verifyResponse(data: ByteArray, id: String, key: ByteArray, nonce: ByteArray, cert: ByteArray, endpoint: PairingEndpoint): PairedHelper {
        val outer = PairingJson.parse(data, 4096)
        require(outer.keys == setOf("v", "nonce", "payload", "proof") && outer["v"] == 1)
        val serverNonce = decode(outer["nonce"] as String, 32)
        val payload = decode(outer["payload"] as String, maximum = 2048)
        val proof = decode(outer["proof"] as String, 32)
        val expected = hmac(key, serverContext, id.toByteArray(Charsets.US_ASCII), byteArrayOf(0), nonce, serverNonce, cert, payload)
        require(MessageDigest.isEqual(proof, expected))
        // The token payload is parsed only after authenticating exact bytes.
        val config = PairingJson.parse(payload, 2048)
        val pin = cert.joinToString("") { "%02x".format(it.toInt() and 255) }
        require(config.keys == setOf("v", "port", "fingerprint", "token") && config["v"] == 1 && config["fingerprint"] == pin)
        require((config["port"] as Int) in 1..65535)
        val token = config["token"] as String
        val utf8 = Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT).encode(java.nio.CharBuffer.wrap(token))
        require(utf8.remaining() in 32..512 && token == token.trim() && token.none { it.code < 32 || it.code == 127 })
        return PairedHelper(endpoint.host, endpoint.port, pin, token)
    }

    fun pair(input: String, code: String, timeoutMillis: Long = 12_000, cancelled: () -> Boolean = { false }): PairedHelper {
        val endpoint = endpoint(input)
        val (id, key) = parseCode(code)
        require(timeoutMillis in 1..30_000)
        val io = SessionIo()
        val expired = AtomicBoolean(false)
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        val watchdog = Executors.newSingleThreadScheduledExecutor { task -> Thread(task, "tgproxy-pair-deadline").apply { isDaemon = true } }
        watchdog.scheduleAtFixedRate({
            if (cancelled()) io.close()
            else if (System.nanoTime() >= deadline) { expired.set(true); io.close() }
            else io.expire(System.nanoTime())
        }, 0, 50, TimeUnit.MILLISECONDS)
        try {
            if (cancelled()) throw PairingException(PairingFailureCode.CANCELLED)
            val bootstrapTrust = object : X509TrustManager {
                override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                    // This is NOT general TLS trust: subsequent code-derived HMAC must
                    // authenticate the exact observed certificate before accepting data.
                    if (chain.isNullOrEmpty() || chain.size > 8 || chain.any { it.encoded.size > 65536 }) throw CertificateException("Pairing certificate unavailable")
                }
                override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) { throw CertificateException() }
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
            val tls = SSLContext.getInstance("TLS").apply { init(null, arrayOf(bootstrapTrust), null) }
            val socket = tlsConnect(endpoint.host, endpoint.port, io, null, tls.socketFactory)
            val cert = MessageDigest.getInstance("SHA-256").digest(socket.session.peerCertificates[0].encoded)
            val nonce = ByteArray(32).also(random::nextBytes)
            val request = "{\"v\":1,\"id\":\"$id\",\"nonce\":\"${encode(nonce)}\",\"proof\":\"${encode(clientProof(key, id, nonce, cert))}\"}".toByteArray(Charsets.US_ASCII)
            val output = DataOutputStream(socket.getOutputStream())
            io.operation("pair-write", HANDSHAKE_TIMEOUT_MS) {
                val magic = "TGPAIR1".toByteArray(Charsets.US_ASCII)
                output.writeInt(magic.size); output.write(magic); output.writeInt(request.size); output.write(request); output.flush()
            }
            val response = io.operation("pair-read", HANDSHAKE_TIMEOUT_MS) {
                val inputStream = socket.getInputStream(); inputStream.exactly(readLength(inputStream, 4096))
            }
            if (cancelled()) throw PairingException(PairingFailureCode.CANCELLED)
            if (expired.get()) throw PairingException(PairingFailureCode.TIMEOUT)
            return verifyResponse(response, id, key, nonce, cert, endpoint)
        } catch (e: PairingException) { throw e }
        catch (_: Exception) {
            throw PairingException(when { cancelled() -> PairingFailureCode.CANCELLED; expired.get() -> PairingFailureCode.TIMEOUT; else -> PairingFailureCode.UNVERIFIED_SERVER })
        } finally { key.fill(0); io.close(); watchdog.shutdownNow() }
    }
}

/** Flat, bounded strict JSON used only by the small pairing envelope/config. */
internal object PairingJson {
    fun parse(bytes: ByteArray, maximum: Int): Map<String, Any> {
        require(bytes.size in 1..maximum)
        val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        var i = 0
        fun white() { while (i < text.length && text[i] in " \r\n\t") i++ }
        fun character(c: Char) { white(); require(i < text.length && text[i++] == c) }
        fun string(): String {
            character('"'); val value = StringBuilder()
            while (i < text.length) {
                val c = text[i++]
                if (c == '"') return value.toString()
                require(c.code >= 32)
                if (c != '\\') { value.append(c); continue }
                require(i < text.length)
                when (val escape = text[i++]) {
                    '"', '\\', '/' -> value.append(escape)
                    'b' -> value.append('\b'); 'f' -> value.append('\u000c'); 'n' -> value.append('\n'); 'r' -> value.append('\r'); 't' -> value.append('\t')
                    'u' -> { require(i + 4 <= text.length && text.substring(i, i + 4).all { it in "0123456789abcdefABCDEF" }); value.append(text.substring(i, i + 4).toInt(16).toChar()); i += 4 }
                    else -> error("Invalid pairing JSON")
                }
            }
            error("Incomplete pairing JSON")
        }
        val result = linkedMapOf<String, Any>()
        character('{'); white()
        if (i < text.length && text[i] == '}') { i++; white(); require(i == text.length); return result }
        while (true) {
            require(result.size < 8)
            val name = string(); require(name !in result); character(':'); white()
            val value: Any = if (i < text.length && text[i] == '"') string() else {
                val start = i
                while (i < text.length && text[i] in '0'..'9') i++
                require(i > start && (i - start == 1 || text[start] != '0'))
                text.substring(start, i).toInt()
            }
            result[name] = value; white(); require(i < text.length)
            if (text[i] == '}') { i++; break }
            character(',')
        }
        white(); require(i == text.length)
        return result
    }
}
