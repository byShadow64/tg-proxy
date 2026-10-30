package io.github.byshadow64.tgproxy.core

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.TimeUnit
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

/** JVM DNS cannot be interrupted. At most two daemon resolutions can be outstanding process-wide. */
internal object BoundedDns {
    private val executor = dnsExecutor()
    private val shared = SharedHostResolver(executor = executor)

    fun resolve(host: String, io: SessionIo): InetAddress = resolveAll(host, io).first()

    fun resolveAll(host: String, io: SessionIo, timeoutMs: Int = 5_000): List<InetAddress> {
        if (io.closed) throw java.io.EOFException()
        ipv4Literal(host)?.let { return listOf(it) }
        if (':' in host && host.all { it in "0123456789abcdefABCDEF:." }) return listOf(InetAddress.getByName(host))
        return shared.resolveAll(host, io, timeoutMs)
    }

    internal fun preferIpv4(addresses: List<InetAddress>): List<InetAddress> {
        val unique = addresses.distinctBy { it.hostAddress }
        if (unique.isEmpty()) throw java.net.UnknownHostException()
        return unique.sortedBy { if (it is java.net.Inet4Address) 0 else 1 }
    }

    internal fun ipv4Literal(host: String): InetAddress? {
        if (host.any { it !in '0'..'9' && it != '.' }) return null
        val parts = host.split('.')
        if (parts.size != 4 || parts.any { it.length !in 1..3 || it.toInt() !in 0..255 }) throw java.net.UnknownHostException()
        return InetAddress.getByAddress(ByteArray(4) { parts[it].toInt().toByte() })
    }
}

internal fun tlsConnect(
    host: String, port: Int, io: SessionIo, domain: String?,
    factory: SSLSocketFactory = SSLContext.getDefault().socketFactory,
    sni: String? = null, timeoutMs: Int = HANDSHAKE_TIMEOUT_MS,
    resolve: (String, SessionIo, Int) -> List<InetAddress> = BoundedDns::resolveAll,
): SSLSocket {
    if (sni != null && (domain == null || !isTelegramOrigin(domain))) throw ProtocolException()
    require(timeoutMs > 0)
    val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs.toLong())
    val addresses = resolve(host, io, remainingConnectMillis(deadline, io))
    val raw = connectResolvedAddresses(addresses, port, io, deadline)
    var tls: SSLSocket? = null
    try {
        val connected = io.track(factory.createSocket(raw, domain ?: host, port, true), raw) as SSLSocket
        tls = connected
        val handshakeTimeout = remainingConnectMillis(deadline, io)
        connected.soTimeout = handshakeTimeout
        connected.enabledProtocols = connected.supportedProtocols.filter { it == "TLSv1.2" || it == "TLSv1.3" }.toTypedArray()
        connected.sslParameters = connected.sslParameters.apply {
            if (domain != null) {
                endpointIdentificationAlgorithm = if (sni == null) "HTTPS" else null
                serverNames = listOf(SNIHostName(sni ?: domain))
            } else {
                endpointIdentificationAlgorithm = null
                serverNames = emptyList()
            }
        }
        io.operation("tls", handshakeTimeout, connected) { connected.startHandshake() }
        if (sni != null) verifyTelegramIdentity(connected.session.peerCertificates[0] as X509Certificate, domain!!)
        connected.soTimeout = 0
        return connected
    } catch (failure: Throwable) {
        // Only TCP failures may advance to another address. TLS identity/pin failures remain fatal.
        // Remove failed sockets from tracking as well as closing their descriptors.
        tls?.let { io.abort(it) }
        io.abort(raw)
        throw failure
    }
}

private fun remainingConnectMillis(deadline: Long, io: SessionIo): Int {
    if (io.closed) throw java.io.EOFException()
    val nanos = deadline - System.nanoTime()
    if (nanos <= 0) throw SocketTimeoutException()
    return ((nanos + 999_999) / 1_000_000).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
}

/** A bad first A/AAAA record must not discard the rest of a host's bounded DNS answer. */
internal fun connectResolvedAddresses(
    addresses: List<InetAddress>, port: Int, io: SessionIo, deadline: Long,
    socketFactory: () -> Socket = ::Socket,
): Socket {
    val candidates = addresses.distinctBy { it.hostAddress }.take(8)
    if (candidates.isEmpty()) throw UnknownHostException()
    var lastFailure: java.io.IOException? = null
    for ((index, address) in candidates.withIndex()) {
        val remaining = remainingConnectMillis(deadline, io)
        // Leave time for other addresses if an early TCP SYN is blackholed. All attempts and
        // the following TLS handshake still share the original caller's setup deadline.
        val timeout = minOf(CONNECT_TIMEOUT_MS, remaining, if (index < candidates.lastIndex) 1_500 else remaining)
        val socket = io.track(socketFactory())
        try {
            socket.tcpNoDelay = true
            socket.receiveBufferSize = STREAM_CHUNK_BYTES; socket.sendBufferSize = STREAM_CHUNK_BYTES
            io.operation("connect", timeout, socket) { socket.connect(InetSocketAddress(address, port), timeout) }
            if (io.closed) throw java.io.EOFException()
            return socket
        } catch (failure: Throwable) {
            io.abort(socket)
            if (io.closed || failure !is java.io.IOException) throw failure
            lastFailure = failure
        }
    }
    throw lastFailure ?: UnknownHostException()
}

private fun isTelegramOrigin(domain: String) = domain.matches(Regex("kws[1-5](?:-1)?\\.web\\.telegram\\.org"))

/** SNI camouflage never relaxes CA trust or accepts a certificate belonging only to that camouflage host. */
internal fun verifyTelegramIdentity(certificate: X509Certificate, domain: String) {
    if (!isTelegramOrigin(domain)) throw javax.net.ssl.SSLPeerUnverifiedException("Invalid Telegram origin")
    val names = try { certificate.subjectAlternativeNames ?: emptyList() } catch (_: Exception) { emptyList() }
    for (entry in names) {
        if (entry.size < 2 || entry[0] != 2 || entry[1] !is String) continue
        val presented = (entry[1] as String).lowercase(Locale.ROOT).trimEnd('.')
        if (matchesTelegramName(presented, domain) || matchesTelegramName(presented, "telegram.org")) return
    }
    throw javax.net.ssl.SSLPeerUnverifiedException("Certificate does not identify Telegram")
}

internal fun matchesTelegramName(presented: String, expected: String): Boolean {
    if (presented == expected) return true
    return presented.startsWith("*.") && presented.count { it == '*' } == 1 && presented.count { it == '.' } >= 2 &&
        expected.count { it == '.' } == presented.count { it == '.' } && expected.substringAfter('.') == presented.substring(2)
}

internal class PinnedTrustManager(private val expected: ByteArray) : X509TrustManager {
    val mismatch = AtomicBoolean(false)
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        if (chain.isNullOrEmpty() || !MessageDigest.isEqual(expected, MessageDigest.getInstance("SHA-256").digest(chain[0].encoded))) {
            mismatch.set(true)
            throw CertificateException("Untrusted helper")
        }
    }
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) { throw CertificateException() }
    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}
