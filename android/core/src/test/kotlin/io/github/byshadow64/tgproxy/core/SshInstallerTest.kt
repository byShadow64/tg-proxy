package io.github.byshadow64.tgproxy.core

import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory
import org.apache.sshd.common.keyprovider.KeyPairProvider
import org.apache.sshd.server.Environment
import org.apache.sshd.server.ExitCallback
import org.apache.sshd.server.SshServer
import org.apache.sshd.server.channel.ChannelSession
import org.apache.sshd.server.command.Command
import org.apache.sshd.server.command.CommandFactory
import org.apache.sshd.sftp.server.SftpFileSystemAccessor
import org.apache.sshd.sftp.server.SftpSubsystemFactory
import org.apache.sshd.sftp.server.SftpSubsystemProxy
import org.junit.Assert.*
import org.junit.Test
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.util.NavigableMap
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** Independent SSH/SFTP implementation over real loopback TCP. Never executes a shell or installer. */
class SshInstallerTest {
    private fun engine(install: Long = 5_000) = SshInstallerEngine(SshTimeouts(preflight = 5_000, authentication = 5_000, upload = 5_000, install = install, total = 15_000))
    private fun rejects(code: SshFailureCode, action: () -> Unit) {
        try { action(); fail("Expected safe SSH rejection") } catch (failure: SshException) { assertEquals(code, failure.code); assertNull(failure.cause); assertEquals(code.name, failure.message) }
    }
    private fun deploy(fixture: Fixture, preview: SshHostKey = engine().preflight(fixture.endpoint(), { false }, {}), password: CharArray = Fixture.PASSWORD.toCharArray(), cancelled: () -> Boolean = { false }, engine: SshInstallerEngine = engine(), progress: (SshInstallProgress) -> Unit = {}): SshInstallResult =
        engine.deploy(fixture.endpoint(), password, preview, SshValidationTest.payload(), fixture.options(), cancelled, progress)

    @Test fun preflightProvesHostKeyWithoutAnyAuthenticationAndExactConfirmedKeyDeploysSftp() {
        Fixture().use { server ->
            val preview = engine().preflight(server.endpoint(), { false }, {})
            assertEquals(0, server.authCalls.get()); assertTrue(preview.sha256Fingerprint.startsWith("SHA256:")); assertEquals("ecdsa-sha2-nistp256", preview.keyType)
            val stages = mutableListOf<SshInstallProgress>(); val password = Fixture.PASSWORD.toCharArray()
            val result = deploy(server, preview, password, progress = stages::add)
            assertEquals(1, server.authCalls.get()); assertEquals("127.0.0.1", result.host); assertEquals(8444, result.port)
            assertTrue(password.all { it == '\u0000' }); assertEquals(SshInstallStage.COMPLETE, stages.last().stage)
            assertTrue(stages.any { it.stage == SshInstallStage.UPLOADING && it.sentBytes > 0 })
            assertEquals(2, server.verifiedPayload.get()); assertFalse(server.commands.any { it.contains(Fixture.PASSWORD) })
            assertTrue(server.commands.last().contains("--registry-mode")); assertFalse(server.commands.last().contains("--allow-existing-private-upgrade"))
            await { server.server.activeSessions.isEmpty() }; assertEquals(0L, Files.list(server.root.resolve("root")).use { it.count() })
        }
    }

    @Test fun ed25519HostKeyUsesAndroidCompatibleLightweightPrimitives() {
        val fixtureProvider = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").getDeclaredConstructor().newInstance() as java.security.Provider
        Fixture(KeyPairGenerator.getInstance("Ed25519", fixtureProvider).generateKeyPair()).use { server ->
            val preview = engine().preflight(server.endpoint(), { false }, {})
            assertEquals("ssh-ed25519", preview.keyType); assertEquals(0, server.authCalls.get())
            deploy(server, preview); assertEquals(1, server.authCalls.get())
        }
    }

    @Test fun substitutedKeyIsRejectedBeforePasswordAuthenticationOrUpload() {
        Fixture().use { server ->
            val preview = engine().preflight(server.endpoint(), { false }, {})
            server.server.keyPairProvider = KeyPairProvider.wrap(Fixture.ec())
            val password = Fixture.PASSWORD.toCharArray()
            rejects(SshFailureCode.HOST_KEY_CHANGED) { deploy(server, preview, password) }
            assertTrue(password.all { it == '\u0000' }); assertEquals(0, server.authCalls.get()); assertTrue(server.commands.isEmpty())
            assertEquals(0L, Files.list(server.root.resolve("root")).use { it.count() })
        }
    }

    @Test fun wrongPasswordFailsOnceAndNeverUploadsOrExecutes() {
        Fixture().use { server ->
            val password = "wrong-synthetic-password".toCharArray()
            rejects(SshFailureCode.AUTHENTICATION_FAILED) { deploy(server, password = password) }
            assertTrue(password.all { it == '\u0000' }); assertEquals(1, server.authCalls.get()); assertTrue(server.commands.isEmpty())
        }
    }

    @Test fun nonRootAccountReturnsRootRequiredBeforeAnyUpload() {
        Fixture().use { server ->
            server.uid = "1000\n"
            rejects(SshFailureCode.ROOT_REQUIRED) { deploy(server) }
            assertEquals(listOf("/usr/bin/id -u"), server.commands.toList()); assertEquals(0L, Files.list(server.root.resolve("root")).use { it.count() })
        }
    }

    @Test fun forgedRootIdOutputCannotPassByCaptureTruncation() {
        Fixture().use { server ->
            server.uid = "0" + " ".repeat(40) + "1000"
            rejects(SshFailureCode.INSTALL_FAILED) { deploy(server) }
            assertEquals(1, server.commands.size); assertEquals(0L, Files.list(server.root.resolve("root")).use { it.count() })
        }
    }

    @Test fun installerFailureAndUntrustedReceiptAreSafeErrorsAndStageIsCleaned() {
        Fixture().use { server ->
            server.installStatus = 23
            rejects(SshFailureCode.INSTALL_FAILED) { deploy(server) }
            assertEquals(0L, Files.list(server.root.resolve("root")).use { it.count() })
        }
        Fixture().use { server ->
            server.result = server.result.replace("127.0.0.1", "192.0.2.11")
            rejects(SshFailureCode.UNVERIFIED_RESULT) { deploy(server) }
            assertEquals(0L, Files.list(server.root.resolve("root")).use { it.count() })
        }
    }

    @Test fun permissiveOrWrongOwnerResultFileIsRejected() {
        Fixture().use { server ->
            server.resultWorldReadable = true
            rejects(SshFailureCode.UNVERIFIED_RESULT) { deploy(server) }
        }
        Fixture().use { server ->
            server.resultOwner = 1000
            rejects(SshFailureCode.UNVERIFIED_RESULT) { deploy(server) }
        }
    }

    @Test fun installerDeadlineClosesActualSshSessionAndDoesNotDeleteRunningInputs() {
        Fixture().use { server ->
            server.holdInstall = true
            val started = System.nanoTime()
            rejects(SshFailureCode.TIMEOUT) { deploy(server, engine = engine(300)) }
            assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) < 5_000)
            await { server.server.activeSessions.isEmpty() }
            assertTrue(Files.list(server.root.resolve("root")).use { it.count() } > 0)
        }
    }

    @Test fun endpointReceiptBindingRejectsWrongPublicIpBeforeAuthentication() {
        Fixture().use { server ->
            val preview = engine().preflight(server.endpoint(), { false }, {}); val password = Fixture.PASSWORD.toCharArray()
            rejects(SshFailureCode.INVALID_REQUEST) {
                engine().deploy(server.endpoint(), password, preview, SshValidationTest.payload(), SshValidationTest.options(), { false }, {})
            }
            assertEquals(0, server.authCalls.get()); assertTrue(password.all { it == '\u0000' }); assertTrue(server.commands.isEmpty())
        }
    }

    @Test fun threadInterruptionIsCancellationAndOutputFloodIsBounded() {
        Fixture().use { server ->
            val preview = engine().preflight(server.endpoint(), { false }, {})
            rejects(SshFailureCode.CANCELLED) {
                try {
                    deploy(server, preview, progress = { if (it.stage == SshInstallStage.CHECKING_PRIVILEGES) { Thread.currentThread().interrupt(); throw InterruptedException() } })
                } finally { Thread.interrupted() }
            }
        }
        Fixture().use { server ->
            server.floodOutput = true
            rejects(SshFailureCode.INSTALL_FAILED) { deploy(server) }
            await { server.server.activeSessions.isEmpty() }
        }
    }

    @Test fun cancelDuringInstallerClosesTcpChannelsAndClearsPassword() {
        Fixture().use { server ->
            server.holdInstall = true
            val preview = engine().preflight(server.endpoint(), { false }, {}); val cancel = AtomicBoolean(); val password = Fixture.PASSWORD.toCharArray()
            val pool = Executors.newSingleThreadExecutor()
            try {
                val task = pool.submit<SshFailureCode> { try { deploy(server, preview, password, cancel::get); error("Unexpected success") } catch (failure: SshException) { failure.code } }
                assertTrue(server.installerEntered.await(5, TimeUnit.SECONDS)); cancel.set(true)
                assertEquals(SshFailureCode.CANCELLED, task.get(3, TimeUnit.SECONDS)); assertTrue(password.all { it == '\u0000' })
                await { server.server.activeSessions.isEmpty() }
            } finally { cancel.set(true); pool.shutdownNow() }
        }
    }

    @Test fun blackholedBannerHasBoundedDeadlineAndCancelClosesPendingSocket() {
        for (cancelEarly in listOf(false, true)) {
            ServerSocket(0, 8, InetAddress.getLoopbackAddress()).use { listener ->
                val accepted = CountDownLatch(1); val closed = CountDownLatch(1); val cancel = AtomicBoolean(); val pool = Executors.newFixedThreadPool(2)
                try {
                    val socket = pool.submit { listener.accept().use { peer -> accepted.countDown(); peer.soTimeout = 3_000; while (peer.getInputStream().read() >= 0) {} }; closed.countDown() }
                    val task = pool.submit<SshFailureCode> {
                        try { SshInstallerEngine(SshTimeouts(preflight = 500)).preflight(SshEndpoint("127.0.0.1", listener.localPort), cancel::get, {}); error("Unexpected success") }
                        catch (failure: SshException) { failure.code }
                    }
                    assertTrue(accepted.await(2, TimeUnit.SECONDS)); if (cancelEarly) cancel.set(true)
                    assertEquals(if (cancelEarly) SshFailureCode.CANCELLED else SshFailureCode.TIMEOUT, task.get(3, TimeUnit.SECONDS))
                    assertTrue(closed.await(2, TimeUnit.SECONDS)); socket.get(1, TimeUnit.SECONDS)
                } finally { cancel.set(true); pool.shutdownNow() }
            }
        }
    }

    private class Fixture(key: KeyPair = ec()) : AutoCloseable {
        val root: Path = Files.createTempDirectory("tgproxy-ssh-fixture-")
        val server = SshServer.setUpDefaultServer()
        val authCalls = AtomicInteger(); val verifiedPayload = AtomicInteger(); val commands = CopyOnWriteArrayList<String>()
        val installerEntered = CountDownLatch(1)
        @Volatile var uid = "0\n"; @Volatile var installStatus = 0; @Volatile var holdInstall = false; @Volatile var floodOutput = false
        @Volatile var resultWorldReadable = false; @Volatile var resultOwner = 0
        @Volatile var result = """{"host":"127.0.0.1","port":8444,"fingerprint":"${"ab".repeat(32)}","registry":true,"helper_id":"${RegistryCrypto.encode(ByteArray(16) { 7 })}"}"""
        private val modes = ConcurrentHashMap<String, Set<PosixFilePermission>>()
        init {
            Files.createDirectories(root.resolve("root")); server.host = "127.0.0.1"; server.port = 0
            server.keyPairProvider = KeyPairProvider.wrap(key)
            server.passwordAuthenticator = org.apache.sshd.server.auth.password.PasswordAuthenticator { username, password, _ -> authCalls.incrementAndGet(); username == "root" && password == PASSWORD }
            server.fileSystemFactory = VirtualFileSystemFactory(root)
            val accessor = object : SftpFileSystemAccessor {
                override fun resolveReportedFileAttributes(subsystem: SftpSubsystemProxy, file: Path, flags: Int, attrs: NavigableMap<String, Any>, vararg options: LinkOption): NavigableMap<String, Any> {
                    attrs["uid"] = if (file.fileName.toString() == "result.json") resultOwner else 0; attrs["gid"] = 0
                    attrs["permissions"] = if (file.fileName.toString() == "result.json" && resultWorldReadable) PosixFilePermission.entries.toSet() else modes[file.toString()] ?: if (Files.isDirectory(file)) DIR_MODE else FILE_MODE
                    return attrs
                }
                override fun setFileAttribute(subsystem: SftpSubsystemProxy, file: Path, view: String, attribute: String, value: Any?, vararg options: LinkOption) {
                    if (attribute == "permissions") {
                        @Suppress("UNCHECKED_CAST") val permissions = value as Set<PosixFilePermission>
                        modes[file.toString()] = permissions
                    }
                    else super.setFileAttribute(subsystem, file, view, attribute, value, *options)
                }
            }
            server.subsystemFactories = listOf(SftpSubsystemFactory.Builder().withFileSystemAccessor(accessor).build())
            server.commandFactory = CommandFactory { _, command -> commands += command; FixtureCommand(command) }
            server.start()
        }
        fun endpoint() = SshEndpoint("127.0.0.1", server.port, "root")
        fun options() = SshValidationTest.options().let { SshInstallOptions(it.registryUrl, it.registryTrustSpki, endpoint().ip, true) }
        private inner class FixtureCommand(private val command: String) : Command {
            private lateinit var out: OutputStream; private lateinit var error: OutputStream; private lateinit var callback: ExitCallback
            private var worker: Thread? = null
            override fun setInputStream(stream: InputStream) {}
            override fun setOutputStream(stream: OutputStream) { out = stream }
            override fun setErrorStream(stream: OutputStream) { error = stream }
            override fun setExitCallback(value: ExitCallback) { callback = value }
            override fun start(channel: ChannelSession, env: Environment) {
                worker = Thread({
                    try {
                        if (command == "/usr/bin/id -u") { out.write(uid.toByteArray()); out.flush(); callback.onExit(0); return@Thread }
                        require(command.contains("/usr/bin/sha256sum --check --strict --status 'payload.sha256'"))
                        val stage = Regex("^cd -- '(/root/\\.tgproxy-setup-[0-9a-f]{32})'").find(command)!!.groupValues[1]
                        val directory = root.resolve(stage.removePrefix("/"))
                        for (line in Files.readAllLines(directory.resolve("payload.sha256"))) {
                            val path = line.substring(66); val expected = line.substring(0, 64)
                            val actual = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(directory.resolve(path))).joinToString("") { "%02x".format(it.toInt() and 255) }
                            require(expected == actual); verifiedPayload.incrementAndGet()
                        }
                        installerEntered.countDown()
                        while (holdInstall) Thread.sleep(25)
                        if (installStatus == 0) Files.writeString(directory.resolve("result.json"), result)
                        if (floodOutput) { repeat(257) { out.write(ByteArray(4096) { 120 }); out.flush() } }
                        out.write("safe synthetic installer output\n".toByteArray()); out.flush(); callback.onExit(installStatus)
                    } catch (_: InterruptedException) { /* Simulated remote command termination. */ }
                    catch (_: Exception) { try { callback.onExit(99) } catch (_: Exception) {} }
                }, "ssh-fixture-command").apply { isDaemon = true; start() }
            }
            override fun destroy(channel: ChannelSession) { worker?.interrupt() }
        }
        override fun close() {
            server.stop(true)
            require(root.toAbsolutePath().normalize().parent == Path.of(System.getProperty("java.io.tmpdir")).toAbsolutePath().normalize())
            require(root.fileName.toString().startsWith("tgproxy-ssh-fixture-"))
            Files.walk(root).use { stream -> stream.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } }
        }
        companion object {
            const val PASSWORD = "synthetic-pāssword-only"
            private val DIR_MODE = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE)
            private val FILE_MODE = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
            fun ec(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        }
    }
    companion object {
        private fun await(condition: () -> Boolean) {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
            while (!condition() && System.nanoTime() < deadline) Thread.sleep(20)
            assertTrue(condition())
        }
    }
}
