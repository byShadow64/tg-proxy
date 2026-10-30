package io.github.byshadow64.tgproxy.core

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URI
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** Downloads only the compiled HTTPS origin; neither metadata nor redirects can choose another host. */
class HttpsUpdateTransport internal constructor(
    private val origin: String,
    private val factory: SSLSocketFactory,
    private val metadataTimeoutMs: Int = 15_000,
    private val downloadTimeoutMs: Int = 180_000,
) {
    constructor() : this(ORIGIN, SSLContext.getDefault().socketFactory)
    private val base = URI(origin).also {
        require(it.scheme == "https" && !it.host.isNullOrBlank() && it.userInfo == null && it.query == null && it.fragment == null)
        require(it.rawPath.isNullOrEmpty() || it.rawPath == "/")
        require(it.port == -1 || it.port in 1..65535)
        require(metadataTimeoutMs in 1..15_000 && downloadTimeoutMs in 1..180_000)
    }

    fun fetchManifest(cancel: () -> Boolean = { false }): ByteArray {
        val result = ByteArrayOutputStream()
        get("/android-dev/latest.json", AndroidUpdateProtocol.MAX_METADATA_BYTES.toLong(), null, metadataTimeoutMs, cancel) { input, length, check ->
            copy(input, length, check) { bytes, size -> result.write(bytes, 0, size) }
        }
        return result.toByteArray()
    }

    /** The destination must be a new app-private file. Failed/cancelled bytes never become a ready APK. */
    fun download(manifest: AndroidUpdateManifest, destination: File, cancel: () -> Boolean = { false }, progress: (Long, Long) -> Unit = { _, _ -> }) {
        var temporary: File? = null
        try {
            val target = destination.absoluteFile.toPath().normalize()
            val parent = target.parent ?: throw UpdateException(UpdateFailureCode.FILE)
            if (!Files.isDirectory(parent) || Files.isSymbolicLink(parent) || parent.toRealPath() != parent || Files.exists(target, LinkOption.NOFOLLOW_LINKS)) throw UpdateException(UpdateFailureCode.FILE)
            temporary = Files.createTempFile(parent, "tg-update-", ".part").toFile()
            val digest = MessageDigest.getInstance("SHA-256")
            FileOutputStream(temporary).use { output ->
                get(manifest.apkPath, AndroidUpdateProtocol.MAX_APK_BYTES, manifest.size, downloadTimeoutMs, cancel) { input, length, check ->
                    var received = 0L
                    progress(0, length)
                    copy(input, length, check) { bytes, size ->
                        output.write(bytes, 0, size); digest.update(bytes, 0, size); received += size
                        progress(received, length)
                    }
                    check()
                    output.fd.sync()
                }
            }
            val actual = digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
            if (actual != manifest.sha256) throw UpdateException(UpdateFailureCode.HASH)
            if (cancel() || Thread.currentThread().isInterrupted) throw UpdateException(UpdateFailureCode.CANCELLED)
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) throw UpdateException(UpdateFailureCode.FILE)
            try { Files.move(temporary.toPath(), target, StandardCopyOption.ATOMIC_MOVE) }
            catch (_: AtomicMoveNotSupportedException) { Files.move(temporary.toPath(), target) }
            temporary = null
        } catch (failure: UpdateException) { throw failure }
        catch (_: Exception) { throw UpdateException(UpdateFailureCode.FILE) }
        finally { temporary?.delete() }
    }

    private fun get(path: String, maximum: Long, expected: Long?, timeoutMs: Int, cancel: () -> Boolean, consume: (InputStream, Long, () -> Unit) -> Unit) {
        val io = SessionIo()
        val expired = AtomicBoolean(false)
        val cancelled = AtomicBoolean(false)
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs.toLong())
        fun check() {
            if (cancel() || cancelled.get() || Thread.currentThread().isInterrupted) throw UpdateException(UpdateFailureCode.CANCELLED)
            if (expired.get() || System.nanoTime() >= deadline) throw UpdateException(UpdateFailureCode.TIMEOUT)
        }
        check()
        val timer = watchdog.scheduleAtFixedRate({
            if (cancel()) { cancelled.set(true); io.close() }
            else if (System.nanoTime() >= deadline) { expired.set(true); io.close() }
        }, 0, 50, TimeUnit.MILLISECONDS)
        var connection: HttpsURLConnection? = null
        try {
            require(path.startsWith("/android-dev/") && path.none { it.code < 33 || it.code > 126 } && '?' !in path && '#' !in path)
            // Use the platform HTTPS stack on every API. The raw TLS reader failed closed
            // with BAD_RECORD_MAC on API26 while this stack verified the identical APK.
            val current = base.resolve(path).toURL().openConnection() as HttpsURLConnection
            connection = current
            current.instanceFollowRedirects = false
            current.useCaches = false
            current.connectTimeout = minOf(timeoutMs, 10_000)
            current.readTimeout = minOf(timeoutMs, 10_000)
            current.sslSocketFactory = RestrictedSocketFactory(factory, io)
            // Keep the platform hostname verifier; the socket also requires HTTPS identity.
            current.setRequestProperty("Accept-Encoding", "identity")
            current.setRequestProperty("Cache-Control", "no-cache, no-store")
            current.setRequestProperty("Connection", "close")
            check()
            if (current.responseCode != 200) throw UpdateException(UpdateFailureCode.HTTP)
            check()
            val length = headers(current, maximum, expected)
            current.inputStream.use { input ->
                consume(input, length, ::check)
            }
            check()
        } catch (failure: Exception) {
            check()
            when (failure) {
                is UpdateException -> throw failure
                is SSLException -> throw UpdateException(UpdateFailureCode.TLS)
                is SocketTimeoutException -> throw UpdateException(UpdateFailureCode.TIMEOUT)
                else -> throw UpdateException(UpdateFailureCode.NETWORK)
            }
        } finally {
            timer.cancel(false)
            // Close tracked raw descriptors before disconnect, which may wait for a TLS read.
            io.close()
            runCatching { connection?.disconnect() }
        }
    }

    private fun headers(connection: HttpsURLConnection, maximum: Long, expected: Long?): Long {
        var total = 0
        val headers = mutableMapOf<String, String>()
        for ((rawName, values) in connection.headerFields) {
            if (values.size != 1) throw UpdateException(UpdateFailureCode.HTTP)
            val value = values.single()
            if (value.any { it.code !in 32..126 && it != '\t' }) throw UpdateException(UpdateFailureCode.HTTP)
            total += (rawName?.length ?: 0) + value.length + 4
            if (total > 8192) throw UpdateException(UpdateFailureCode.HTTP)
            if (rawName == null) continue // The platform has already parsed the HTTP status line.
            val name = rawName.lowercase(Locale.ROOT)
            if (!name.matches(Regex("[a-z0-9-]+")) || name in headers || headers.size >= 32) throw UpdateException(UpdateFailureCode.HTTP)
            headers[name] = value.trim()
        }
        // This publisher serves immutable files with Content-Length. Reject ambiguous
        // framing/compression instead of accepting unbounded or differently encoded bytes.
        if ("transfer-encoding" in headers || headers["content-encoding"]?.lowercase(Locale.ROOT) !in setOf(null, "identity")) throw UpdateException(UpdateFailureCode.HTTP)
        val lengthText = headers["content-length"] ?: throw UpdateException(UpdateFailureCode.HTTP)
        val length = lengthText.takeIf { it.matches(Regex("[0-9]{1,10}")) }?.toLongOrNull() ?: throw UpdateException(UpdateFailureCode.HTTP)
        if (length !in 1..maximum || expected != null && length != expected) throw UpdateException(UpdateFailureCode.SIZE)
        return length
    }

    /** Returns real platform sockets, retaining platform HTTPS behavior and CA validation. */
    private class RestrictedSocketFactory(private val delegate: SSLSocketFactory, private val io: SessionIo) : SSLSocketFactory() {
        private fun configure(value: Socket, raw: Socket? = null): Socket {
            val socket = io.track(value, raw) as SSLSocket
            socket.enabledProtocols = socket.supportedProtocols.filter { it == "TLSv1.2" || it == "TLSv1.3" }.toTypedArray()
            socket.sslParameters = socket.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
            return socket
        }
        override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites
        override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites
        override fun createSocket(): Socket = configure(delegate.createSocket())
        override fun createSocket(socket: Socket, host: String, port: Int, close: Boolean): Socket {
            io.track(socket)
            return configure(delegate.createSocket(socket, host, port, close), socket)
        }
        override fun createSocket(host: String, port: Int): Socket = configure(delegate.createSocket(host, port))
        override fun createSocket(host: String, port: Int, local: InetAddress, localPort: Int): Socket = configure(delegate.createSocket(host, port, local, localPort))
        override fun createSocket(host: InetAddress, port: Int): Socket = configure(delegate.createSocket(host, port))
        override fun createSocket(host: InetAddress, port: Int, local: InetAddress, localPort: Int): Socket = configure(delegate.createSocket(host, port, local, localPort))
    }

    private fun copy(input: InputStream, length: Long, check: () -> Unit, write: (ByteArray, Int) -> Unit) {
        val buffer = ByteArray(64 * 1024)
        var remaining = length
        while (remaining > 0) {
            check()
            val count = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
            if (count < 0) throw UpdateException(UpdateFailureCode.SIZE)
            if (count == 0) continue
            check(); write(buffer, count); remaining -= count
        }
    }

    companion object {
        const val ORIGIN = "https://217.177.34.28"
        const val MANIFEST_URL = "$ORIGIN/android-dev/latest.json"
        private val watchdog = Executors.newSingleThreadScheduledExecutor { action -> Thread(action, "tg-update-deadlines").apply { isDaemon = true } }
    }
}
