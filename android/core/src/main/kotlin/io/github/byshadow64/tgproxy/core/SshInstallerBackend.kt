package io.github.byshadow64.tgproxy.core

import com.jcraft.jsch.Channel
import com.jcraft.jsch.ChannelExec
import com.jcraft.jsch.ChannelSftp
import com.jcraft.jsch.HostKey
import com.jcraft.jsch.HostKeyRepository
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.jcraft.jsch.UserInfo
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

internal data class SshTimeouts(val preflight: Long = 10_000, val authentication: Long = 12_000, val upload: Long = 30_000, val install: Long = 600_000, val total: Long = 660_000)
internal object SshInstallerBackend {
    private val implementation = SshInstallerEngine()
    fun preflight(endpoint: SshEndpoint, cancelled: () -> Boolean, progress: (SshInstallProgress) -> Unit) = implementation.preflight(endpoint, cancelled, progress)
    fun deploy(endpoint: SshEndpoint, password: CharArray, accepted: SshHostKey, payload: List<SshPayloadFile>, options: SshInstallOptions,
        cancelled: () -> Boolean, progress: (SshInstallProgress) -> Unit) = implementation.deploy(endpoint, password, accepted, payload, options, cancelled, progress)
}

internal class SshInstallerEngine(private val timeouts: SshTimeouts = SshTimeouts()) {
    fun preflight(input: SshEndpoint, cancelled: () -> Boolean, progress: (SshInstallProgress) -> Unit): SshHostKey {
        val endpoint = validateEndpoint(input)
        val repository = ExactHostKeys(endpoint, null)
        SshOperation(timeouts.preflight, cancelled).use { operation ->
            try {
                operation.phase(timeouts.preflight)
                progress(SshInstallProgress(SshInstallStage.CONNECTING))
                val session = session(endpoint, repository, operation)
                progress(SshInstallProgress(SshInstallStage.CHECKING_HOST_KEY))
                // Strict rejection deliberately stops after cryptographically verified KEX and before user authentication.
                try { session.connect(timeouts.preflight.toInt()) } catch (failure: com.jcraft.jsch.JSchException) {
                    if (repository.observed.get() == null) throw failure
                }
                operation.check()
                return repository.observed.get() ?: throw SshException(SshFailureCode.UNSUPPORTED_SERVER)
            } catch (failure: Exception) { throw operation.safeFailure(failure, SshFailureCode.CONNECTION_FAILED) }
        }
    }

    fun deploy(input: SshEndpoint, password: CharArray, accepted: SshHostKey, payload: List<SshPayloadFile>, options: SshInstallOptions,
        cancelled: () -> Boolean, progress: (SshInstallProgress) -> Unit): SshInstallResult {
        var operation: SshOperation? = null
        var sftp: ChannelSftp? = null
        var stage: String? = null
        var installerStarted = false
        var installerFinished = false
        try {
            val endpoint = validateEndpoint(input)
            val expected = validateEndpoint(accepted.endpoint)
            requireRequest(endpoint.ip == expected.ip && endpoint.port == expected.port && endpoint.username == expected.username)
            requireRequest(password.isNotEmpty() && password.size <= 1024 && password.none { it == '\u0000' })
            val checkedOptions = validateOptions(options)
            requireRequest(checkedOptions.publicIp == endpoint.ip)
            validatePayload(payload)
            val op = SshOperation(timeouts.total, cancelled); operation = op
            val repository = ExactHostKeys(endpoint, accepted)
            op.phase(timeouts.authentication)
            progress(SshInstallProgress(SshInstallStage.AUTHENTICATING))
            val connected = session(endpoint, repository, op)
            val encoded = Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(password))
            val passwordBytes = ByteArray(encoded.remaining()).also(encoded::get)
            try {
                connected.setPassword(passwordBytes)
                connected.connect(timeouts.authentication.toInt())
            } catch (failure: Exception) {
                if (repository.changed.get() || failure is com.jcraft.jsch.JSchAlgoNegoFailException) throw SshException(SshFailureCode.HOST_KEY_CHANGED)
                if (failure.message.orEmpty().startsWith("Auth fail") || failure.message.orEmpty().startsWith("Auth cancel")) throw SshException(SshFailureCode.AUTHENTICATION_FAILED)
                throw failure
            } finally { passwordBytes.fill(0); if (encoded.hasArray()) encoded.array().fill(0); password.fill('\u0000') }
            op.check()
            op.phase(5_000)
            progress(SshInstallProgress(SshInstallStage.CHECKING_PRIVILEGES))
            val user = exec(connected, "/usr/bin/id -u", op, 32)
            if (user.status != 0 || user.stdout.toString(Charsets.US_ASCII).trim() != "0") throw SshException(SshFailureCode.ROOT_REQUIRED)
            op.phase(timeouts.upload)
            val channel = connected.openChannel("sftp") as ChannelSftp; sftp = channel; op.track(channel); channel.connect(5_000)
            stage = "/root/.tgproxy-setup-" + ByteArray(16).also(random::nextBytes).joinToString("") { "%02x".format(it.toInt() and 255) }
            channel.mkdir(stage); channel.chmod(448, stage)
            val created = channel.lstat(stage)
            if (!created.isDir || created.isLink || created.getUId() != 0 || created.permissions and 63 != 0) throw SshException(SshFailureCode.INSTALL_FAILED)
            val total = payload.sumOf { it.size }; var sent = 0L
            val directories = payload.flatMap { parentPaths(it.path) }.distinct().sortedBy { it.count { c -> c == '/' } }
            for (directory in directories) { op.check(); channel.mkdir("$stage/$directory"); channel.chmod(448, "$stage/$directory") }
            for (file in payload) {
                op.check()
                progress(SshInstallProgress(SshInstallStage.UPLOADING, sent, total))
                channel.put(ByteArrayInputStream(file.bytes), "$stage/${file.path}", object : com.jcraft.jsch.SftpProgressMonitor {
                    override fun init(opcode: Int, source: String?, destination: String?, maximum: Long) {}
                    override fun count(count: Long): Boolean { op.check(); sent += count; progress(SshInstallProgress(SshInstallStage.UPLOADING, sent, total)); return true }
                    override fun end() {}
                }, ChannelSftp.OVERWRITE)
                channel.chmod(if (file.path.endsWith(".sh")) 448 else 384, "$stage/${file.path}")
                if (channel.lstat("$stage/${file.path}").size != file.size) throw SshException(SshFailureCode.INSTALL_FAILED)
            }
            val manifest = payload.joinToString("\n", postfix = "\n") { "${it.sha256}  ${it.path}" }.toByteArray(Charsets.US_ASCII)
            channel.put(ByteArrayInputStream(manifest), "$stage/payload.sha256"); channel.chmod(384, "$stage/payload.sha256")
            op.phase(timeouts.install)
            progress(SshInstallProgress(SshInstallStage.INSTALLING, total, total))
            installerStarted = true
            val outcome = exec(connected, installerCommand(stage, checkedOptions), op, 0)
            installerFinished = true
            if (outcome.status != 0) throw SshException(SshFailureCode.INSTALL_FAILED)
            op.phase(5_000)
            progress(SshInstallProgress(SshInstallStage.VERIFYING_RESULT))
            val attributes = channel.lstat("$stage/result.json")
            if (!attributes.isReg || attributes.isLink || attributes.getUId() != 0 || attributes.permissions and 63 != 0 || attributes.size !in 1L..4096L) throw SshException(SshFailureCode.UNVERIFIED_RESULT)
            val bytes = channel.get("$stage/result.json").use { stream -> boundedRead(stream, 4096) }
            val result = parseResult(bytes, checkedOptions.publicIp)
            op.check()
            progress(SshInstallProgress(SshInstallStage.COMPLETE, total, total))
            return result
        } catch (failure: Exception) {
            throw operation?.safeFailure(failure, SshFailureCode.INSTALL_FAILED)
                ?: if (failure is SshException) failure else SshException(SshFailureCode.INVALID_REQUEST)
        } finally {
            password.fill('\u0000')
            // A disconnected installer may still be terminating: keep its public inputs private in place, never race their deletion.
            if (stage != null && sftp?.isConnected == true && (!installerStarted || installerFinished)) {
                try { cleanup(sftp, stage, payload) } catch (_: Exception) {}
            }
            operation?.close()
        }
    }

    private fun session(endpoint: SshEndpoint, repository: ExactHostKeys, operation: SshOperation): Session {
        val jsch = JSch().apply { setInstanceLogger(object : com.jcraft.jsch.Logger {
            override fun isEnabled(level: Int) = false
            override fun log(level: Int, message: String?) {}
        }) }
        val session = jsch.getSession(endpoint.username, endpoint.ip, endpoint.port)
        operation.session.set(session)
        session.setHostKeyRepository(repository)
        session.setSocketFactory(object : com.jcraft.jsch.SocketFactory {
            override fun createSocket(host: String, port: Int): Socket {
                operation.check()
                val address = BoundedDns.resolve(endpoint.ip, operation.io)
                val socket = operation.io.track(Socket()); socket.tcpNoDelay = true
                operation.io.operation("ssh-connect", 8_000, socket) { socket.connect(InetSocketAddress(address, endpoint.port), 8_000) }
                return socket
            }
            override fun getInputStream(socket: Socket) = socket.getInputStream()
            override fun getOutputStream(socket: Socket) = socket.getOutputStream()
        })
        session.setConfig("StrictHostKeyChecking", "yes")
        session.setConfig("PreferredAuthentications", "password")
        session.setConfig("MaxAuthTries", "1")
        session.setConfig("ClearAllForwardings", "yes")
        session.setConfig("compression.s2c", "none"); session.setConfig("compression.c2s", "none")
        session.setConfig("server_host_key", repository.acceptedAlgorithms())
        // Lightweight BC primitives work on API 26 without replacing Android's global security providers.
        session.setConfig("ssh-ed25519", "com.jcraft.jsch.bc.SignatureEd25519")
        session.setConfig("xdh", "com.jcraft.jsch.bc.XDH")
        session.setServerAliveInterval(10_000); session.setServerAliveCountMax(2); session.setDaemonThread(true)
        return session
    }

    private data class ExecResult(val status: Int, val stdout: ByteArray)
    private fun exec(session: Session, command: String, operation: SshOperation, capture: Int): ExecResult {
        val channel = session.openChannel("exec") as ChannelExec
        operation.track(channel)
        val output = BoundedOutput(capture, if (capture > 0) capture.toLong() else 1024 * 1024)
        val error = BoundedOutput(0, 1024 * 1024)
        try {
            channel.setPty(false); channel.setAgentForwarding(false); channel.setCommand(command)
            channel.setInputStream(ByteArrayInputStream(ByteArray(0)), true)
            channel.setOutputStream(output, true); channel.setErrStream(error, true)
            channel.connect(5_000)
            while (!channel.isClosed) { operation.check(); if (output.exceeded.get() || error.exceeded.get()) throw SshException(SshFailureCode.INSTALL_FAILED); Thread.sleep(25) }
            operation.check()
            if (output.exceeded.get() || error.exceeded.get()) throw SshException(SshFailureCode.INSTALL_FAILED)
            return ExecResult(channel.exitStatus, output.bytes())
        } finally { channel.disconnect(); operation.channels.remove(channel) }
    }

    companion object {
        private val random = SecureRandom()
        internal fun validateEndpoint(input: SshEndpoint): SshEndpoint = try {
            require(input.port in 1..65535 && input.username.matches(Regex("[A-Za-z_][A-Za-z0-9_-]{0,31}")))
            require(input.ip == input.ip.trim())
            SshEndpoint(HelperRegistryClient.numericIp(input.ip), input.port, input.username)
        } catch (_: Exception) { throw SshException(SshFailureCode.INVALID_REQUEST) }
        private fun requireRequest(value: Boolean) { if (!value) throw SshException(SshFailureCode.INVALID_REQUEST) }
        internal fun validateOptions(options: SshInstallOptions): SshInstallOptions = try {
            require(options.allowRegisteredDevices)
            val uri = URI(options.registryUrl)
            require(uri.scheme == "https" && !uri.host.isNullOrEmpty() && uri.userInfo == null && uri.query == null && uri.fragment == null && uri.rawPath in listOf(null, "", "/"))
            require(uri.port == -1 || uri.port in 1..65535)
            RegistryCrypto.p256Key(RegistryCrypto.decode(options.registryTrustSpki, maximum = 256))
            SshInstallOptions(options.registryUrl, options.registryTrustSpki, HelperRegistryClient.numericIp(options.publicIp), true, options.allowExistingPrivateUpgrade)
        } catch (_: Exception) { throw SshException(SshFailureCode.INVALID_REQUEST) }
        internal fun validatePayload(files: List<SshPayloadFile>) {
            try {
                require(files.size in 1..64 && files.map { it.path }.toSet().size == files.size && files.any { it.path == "deploy_helper.sh" })
                require(files.sumOf { it.size } in 1..16L * 1024 * 1024)
                files.forEach {
                    require(it.path.matches(Regex("[A-Za-z0-9_][A-Za-z0-9._/-]{0,199}")))
                    require(it.path.split('/').none { segment -> segment.isEmpty() || segment == "." || segment == ".." || segment.startsWith('.') })
                    require(it.path !in setOf("payload.sha256", "result.json") && it.size <= 4L * 1024 * 1024)
                    require(it.sha256.matches(Regex("[0-9a-f]{64}")))
                    val actual = MessageDigest.getInstance("SHA-256").digest(it.bytes).joinToString("") { byte -> "%02x".format(byte.toInt() and 255) }
                    require(actual == it.sha256)
                }
            } catch (_: Exception) { throw SshException(SshFailureCode.INVALID_PAYLOAD) }
        }
        private fun parentPaths(path: String): List<String> = path.split('/').dropLast(1).runningFold("") { parent, part -> if (parent.isEmpty()) part else "$parent/$part" }.drop(1)
        private fun quote(value: String) = "'" + value.replace("'", "'\"'\"'") + "'"
        internal fun installerCommand(stage: String, options: SshInstallOptions): String {
            require(stage.matches(Regex("/root/\\.tgproxy-setup-[0-9a-f]{32}")))
            return "cd -- ${quote(stage)} && /usr/bin/sha256sum --check --strict --status 'payload.sha256' && /bin/bash './deploy_helper.sh' --registry-mode --registry-url ${quote(options.registryUrl)} --registry-trust-spki ${quote(options.registryTrustSpki)} --public-ip ${quote(options.publicIp)} --result-file ${quote("$stage/result.json")}" +
                if (options.allowExistingPrivateUpgrade) " --allow-existing-private-upgrade" else ""
        }
        internal fun parseResult(bytes: ByteArray, expectedIp: String): SshInstallResult = try {
            val data = SshResultJson.parse(bytes)
            require(data.keys == setOf("host", "port", "fingerprint", "registry", "helper_id") && data["registry"] == true)
            val host = HelperRegistryClient.numericIp(data["host"] as String); require(host == expectedIp)
            val port = data["port"] as Int; require(port in 1..65535)
            val pin = data["fingerprint"] as String; require(pin.matches(Regex("[0-9a-f]{64}")))
            val id = data["helper_id"] as String; RegistryCrypto.decode(id, 16)
            SshInstallResult(host, port, pin, id)
        } catch (_: Exception) { throw SshException(SshFailureCode.UNVERIFIED_RESULT) }
        private fun boundedRead(input: InputStream, limit: Int): ByteArray {
            val result = ByteArrayOutputStream(); val buffer = ByteArray(1024)
            while (true) { val count = input.read(buffer); if (count < 0) break; if (result.size() + count > limit) throw SshException(SshFailureCode.UNVERIFIED_RESULT); result.write(buffer, 0, count) }
            return result.toByteArray()
        }
        private fun cleanup(sftp: ChannelSftp, stage: String, payload: List<SshPayloadFile>) {
            require(stage.matches(Regex("/root/\\.tgproxy-setup-[0-9a-f]{32}")))
            (payload.map { it.path } + listOf("payload.sha256", "result.json")).forEach { try { sftp.rm("$stage/$it") } catch (_: Exception) {} }
            payload.flatMap { parentPaths(it.path) }.distinct().sortedByDescending { it.length }.forEach { try { sftp.rmdir("$stage/$it") } catch (_: Exception) {} }
            sftp.rmdir(stage)
        }
    }
}

private class ExactHostKeys(private val endpoint: SshEndpoint, private val accepted: SshHostKey?) : HostKeyRepository {
    val observed = AtomicReference<SshHostKey?>(); val changed = AtomicBoolean()
    override fun check(host: String?, key: ByteArray): Int {
        val type = HostKey(endpoint.ip, key).type
        observed.set(SshHostKey(endpoint, type, key))
        if (accepted == null) return HostKeyRepository.NOT_INCLUDED
        return if (MessageDigest.isEqual(accepted.encoded, key)) HostKeyRepository.OK else { changed.set(true); HostKeyRepository.CHANGED }
    }
    fun acceptedAlgorithms(): String = when (accepted?.keyType) {
        null -> "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256"
        "ssh-rsa" -> "rsa-sha2-512,rsa-sha2-256"
        "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521" -> accepted.keyType
        else -> throw SshException(SshFailureCode.UNSUPPORTED_SERVER)
    }
    override fun add(hostkey: HostKey?, ui: UserInfo?) { throw IllegalStateException("SSH_AUTOTRUST_FORBIDDEN") }
    override fun remove(host: String?, type: String?) {}
    override fun remove(host: String?, type: String?, key: ByteArray?) {}
    override fun getKnownHostsRepositoryID() = "tgproxy-confirmed-key-memory-only"
    override fun getHostKey(): Array<HostKey> = emptyArray()
    override fun getHostKey(host: String?, type: String?): Array<HostKey> = emptyArray()
}

private class SshOperation(totalMillis: Long, private val cancelled: () -> Boolean) : AutoCloseable {
    val io = SessionIo(); val session = AtomicReference<Session?>(); val channels = ConcurrentHashMap.newKeySet<Channel>()
    private val owner = Thread.currentThread(); private val stopped = AtomicBoolean(); private val expired = AtomicBoolean()
    private val total = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(totalMillis)
    private val phase = AtomicLong(total)
    private val watcher = Executors.newSingleThreadScheduledExecutor { task -> Thread(task, "tgproxy-ssh-deadline").apply { isDaemon = true } }
    init { watcher.scheduleAtFixedRate({
        if (isCancelled()) { stopped.set(true); abort() }
        else if (System.nanoTime() >= minOf(total, phase.get())) { expired.set(true); abort() }
        else io.expire(System.nanoTime())
    }, 0, 50, TimeUnit.MILLISECONDS) }
    fun phase(millis: Long) { phase.set(minOf(total, System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(millis))); check() }
    fun track(channel: Channel) { check(); channels += channel }
    private fun isCancelled() = stopped.get() || owner.isInterrupted || try { cancelled() } catch (_: Exception) { true }
    fun check() {
        if (isCancelled()) throw SshException(SshFailureCode.CANCELLED)
        if (expired.get() || System.nanoTime() >= minOf(total, phase.get())) throw SshException(SshFailureCode.TIMEOUT)
    }
    fun safeFailure(failure: Exception, fallback: SshFailureCode): SshException {
        if (failure is InterruptedException) { owner.interrupt(); return SshException(SshFailureCode.CANCELLED) }
        if (isCancelled()) return SshException(SshFailureCode.CANCELLED)
        if (expired.get() || System.nanoTime() >= minOf(total, phase.get()) || generateSequence(failure as Throwable?) { it.cause }.any { it is java.net.SocketTimeoutException }) return SshException(SshFailureCode.TIMEOUT)
        if (failure is SshException) return failure
        return SshException(fallback)
    }
    private fun abort() {
        io.close()
        channels.forEach { try { it.disconnect() } catch (_: Exception) {} }
        try { session.get()?.disconnect() } catch (_: Exception) {}
    }
    override fun close() { watcher.shutdownNow(); abort() }
}

private class BoundedOutput(private val capture: Int, private val maximum: Long) : OutputStream() {
    private val count = AtomicLong(); private val output = ByteArrayOutputStream(); val exceeded = AtomicBoolean()
    override fun write(value: Int) = write(byteArrayOf(value.toByte()), 0, 1)
    @Synchronized override fun write(bytes: ByteArray, offset: Int, length: Int) {
        if (count.addAndGet(length.toLong()) > maximum) { exceeded.set(true); throw java.io.IOException("SSH_OUTPUT_LIMIT") }
        val keep = minOf(length, (capture - output.size()).coerceAtLeast(0))
        if (keep > 0) output.write(bytes, offset, keep)
    }
    @Synchronized fun bytes(): ByteArray = output.toByteArray()
}
