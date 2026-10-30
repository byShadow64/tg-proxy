package io.github.byshadow64.tgproxy.core

import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyFactory
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext

/** Synthetic loopback fixture key. Never used for a real endpoint or packaged with the application. */
internal object TlsFixture {
    private const val CERT = "MIIC4jCCAcqgAwIBAgIEeMPfrTANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDDBhURyBQcm94eSBMT0NBTCBURVNUIE9OTFkwHhcNMjAwMTAxMDAwMDAwWhcNNDAwMTAxMDAwMDAwWjAjMSEwHwYDVQQDDBhURyBQcm94eSBMT0NBTCBURVNUIE9OTFkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCkEX4FYQm/P6+TqNM0KQQh99MYSP2tSIMI1kvQnFvenAbJ2OsJBGF36wMYOpLUDzYFVQ8D8lmKaT03E3mrln0P4TcAtfwT7g7E+U83roAr+Wes2t1O7bk8QFhQUJv8CQ3QffY9SCVaoTbBNlNqEYSQ/iiuRUPWr6YKdBXbsppL5O7vidZcCHqlMP1dDclxTYx5jblXWs7bi7+emJh/GEQ3E9hOVB7wWJIljX4GpBtd830BZS9XSGUnBRiF4TXJlNeCaAc+moYynQFks58QHPwk+ZDXAxsDXuleWp9KKGxuQtWy9i/cTNp9vjY8FaZldKvztOxqaYPG3aPyWUohiD8xAgMBAAGjHjAcMBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAOT//tebtuGsCIgtd6FzCK5LXHzOyYMp2EMdYMFrcIBCJf4Hp8APiM18/xpA1ossByUi35PdLXRD8wtWQScRGquJflFyg4u/RmQEKit4Wxu4NAsGCJKPc1JeqXV3jWSFZsQiDlasKQoVZAlkhGwHlfWMOfwfhlt/4+thNaOkrYhcYcrPLdjDbIBVUZU57zoZgT7aZoNcJBXij+h9oD+HPd1qO3rbIutqrTRzN+/p64gf503H9pkI8PJE1VyvUcuo+D2F30V8k2/FO8u7ISxHnECqiIefbCn6s/BIovKllT9ZAGXttFDcG3kf2BOjq1yfBxGDGyHAGoUghrILmeOXdUA=="
    private const val KEY = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCkEX4FYQm/P6+TqNM0KQQh99MYSP2tSIMI1kvQnFvenAbJ2OsJBGF36wMYOpLUDzYFVQ8D8lmKaT03E3mrln0P4TcAtfwT7g7E+U83roAr+Wes2t1O7bk8QFhQUJv8CQ3QffY9SCVaoTbBNlNqEYSQ/iiuRUPWr6YKdBXbsppL5O7vidZcCHqlMP1dDclxTYx5jblXWs7bi7+emJh/GEQ3E9hOVB7wWJIljX4GpBtd830BZS9XSGUnBRiF4TXJlNeCaAc+moYynQFks58QHPwk+ZDXAxsDXuleWp9KKGxuQtWy9i/cTNp9vjY8FaZldKvztOxqaYPG3aPyWUohiD8xAgMBAAECggEAB+afvvqRUZhriBzVLunavRgGHmFFdhbL2J0ZQY6GDg5NdWLwzppbZz72AzCu6W9iFpemBXaiQTwYKpLRhSXWF/GsiGg7H2qTY4DuA6xvl66HA5f2mFpyVSh0GEoJePWmqKeoOANFaTviOyO2mKEHVUQoCVxki+4hfNdiRhYvv//ObwFRZhwk9axuClwp6w6vTcW0lPAWSqmO52WMsFJ2ozpqHDazBoXzGZVe3+J3d0BcPNSXRrOr6ENUPug7o5b9XneqrzgcYR/7ELZVKZpBl6iaczJE78FLXq4DIhUoqM+P/Uz/lQVsmF8ptcQtpIX9bcJtsoJc5bw3nWkF4MfcwQKBgQDnjYooS7eQCieaFcgcQfrNyC1KVpxorQbshQUNZtuIHcRWkHSMGoHT/CMnFJTv7QPen4//MmrdeQC+3bpuGiuB79mCCqhBNyQpSYphNNULyrlWIW6/APUI089dAzx6zm2NgcjwvgwLVGvaa/vWdb1RlZP/VnMNHnbnavMo79mF9QKBgQC1Y/c2DzevFOvikL8AonVFTqiY9+3VP7o70s6Wn5s8xday2Lzq/VgSPDIrsLvV9+0QfveSg150N6aKJQe/6Zns+kzivPd+T82DXY/xnQgV1bFLmPf1UMCUS3yC1k9Uv+/SqsUF2WK/Hfw1IGoAjHX6WPLlig/R0tC5zRs8oIHSzQKBgQDXypx6uTW00wHdI3d+fi7SID+1C8pv8vCE8+KlfroQvE0Br1YuS3W6rTvFa/TxNB1rF6EG32GgTOhY+CKKAXGSgoheHLh5Ln5Qy+xecvIpLyBSGI4xCx9QvrR9pkpy2HZYbh9p3HM1C9QHlqL4Vnm80n0+dL5792wwdwdtmzlJEQKBgQCelNb8HDHCj7fqTEGwfFeqUCp2EcuMNDrNMnAKn19Ism4RzgrcJsFor9fs+oY9epN3aIlpPhDF6iFfhSBRWBmKZQny8OIvO/Wgc5v00CTRchGe1g1yGzdCbvxcJqEUpvk0ZLf7dSIvlDd6+uuxrxs1064Hn7xU5Mo2pmq5hln5wQKBgQCrTPEd5+LpEDeyAGxe/gFV9007HJp0YThaLZxfH/akatLqt6QQoTloswShiwZhd/5vr4cn33eLLfqfEU7kz9SCcZCwP2jDKhyaOAGPO/jRcGGnRt3lTFcozaeotDSmeiwo7S66s4PjwpZrmmSOYgCgCzaI0rBsrL4JKHqfvOZtbg=="
    private val certificate = CertificateFactory.getInstance("X.509").generateCertificate(Base64.getDecoder().decode(CERT).inputStream())
    val pin: String = MessageDigest.getInstance("SHA-256").digest(certificate.encoded).joinToString("") { "%02x".format(it.toInt() and 255) }
    val serverContext: SSLContext by lazy {
        val store = KeyStore.getInstance("JKS").apply { load(null); setKeyEntry("fixture", KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(KEY))), "fixture".toCharArray(), arrayOf(certificate)) }
        val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, "fixture".toCharArray()) }
        SSLContext.getInstance("TLS").apply { init(keys.keyManagers, null, null) }
    }
    val clientFactory get() = SSLContext.getInstance("TLS").apply { init(null, arrayOf(PinnedTrustManager(hex(pin))), null) }.socketFactory
    fun server(body: (Socket) -> Unit) = LocalServer(serverContext.serverSocketFactory.createServerSocket(0, 1, InetAddress.getByAddress(byteArrayOf(127,0,0,1))), body)
}

internal class LocalServer(private val server: ServerSocket = ServerSocket(0, 1, InetAddress.getByAddress(byteArrayOf(127,0,0,1))), body: (Socket) -> Unit) : AutoCloseable {
    val port = server.localPort
    val failure = AtomicReference<Throwable?>()
    private val done = CountDownLatch(1)
    @Volatile private var accepted: Socket? = null
    init {
        Thread({
            try { server.accept().use { socket -> accepted = socket; socket.soTimeout = 3_000; body(socket) } }
            catch (error: Throwable) { failure.set(error) }
            finally { done.countDown() }
        }, "local-fixture").apply { isDaemon = true; start() }
    }
    fun awaitDone() { check(done.await(5, TimeUnit.SECONDS)) { "Fixture timed out" } }
    fun assertSuccess() { awaitDone(); failure.get()?.let { throw AssertionError("Local fixture failed", it) } }
    override fun close() { server.close(); accepted?.close(); done.await(2, TimeUnit.SECONDS) }
}

internal fun writeHelper(socket: Socket, data: ByteArray) {
    val size = data.size
    socket.getOutputStream().apply { write(byteArrayOf((size ushr 24).toByte(), (size ushr 16).toByte(), (size ushr 8).toByte(), size.toByte())); write(data); flush() }
}
internal fun readHelper(socket: Socket): ByteArray = socket.getInputStream().let { it.exactly(readLength(it)) }
