package io.github.byshadow64.tgproxy

import android.app.job.JobScheduler
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build
import android.os.Bundle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.byshadow64.tgproxy.core.AndroidUpdateProtocol
import io.github.byshadow64.tgproxy.core.HttpsUpdateTransport
import io.github.byshadow64.tgproxy.core.UpdateException
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.BufferedInputStream
import java.io.FilterInputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.Socket
import java.net.URL
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.Executors
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.HandshakeCompletedListener
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlinx.coroutines.*

/** Tests operate only on the selected owned emulator and keep the proxy profile untouched. */
@RunWith(AndroidJUnit4::class)
class UpdateRuntimeInstrumentedTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private fun waitFor(timeout: Long = 15000, predicate: () -> Boolean) {
        val deadline = System.nanoTime() + timeout * 1000000
        while (!predicate() && System.nanoTime() < deadline) Thread.sleep(50)
        assertTrue("UPDATE_STATE_TIMEOUT", predicate())
    }
    private fun emit(name: String, value: JSONObject) {
        InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
            putString("tgproxy_receipt_name", name); putString("tgproxy_receipt_json", value.toString())
        })
    }

    /** Only public updater state: no URLs, profile values, certificate data or secrets. */
    private fun emitUpdateState(name: String, automatic: Boolean, phases: Set<String>) {
        val value = UpdateManager.state.value
        val errorName = if (value.errorRes == 0) "none" else
            runCatching { context.resources.getResourceEntryName(value.errorRes) }.getOrDefault("unknown")
        emit(name, JSONObject().put("api", Build.VERSION.SDK_INT).put("automatic", automatic)
            .put("phase", value.phase.name).put("errorResource", errorName)
            .put("bytes", value.bytes).put("total", value.total).put("busy", value.busy)
            .put("observedPhases", phases.joinToString(",")).put("privateFixture", true))
    }

    @Test fun automaticPreferenceSchedulesAndCancelsOnlyOwnJobs() {
        val prefs = context.getSharedPreferences("verified_updates", Context.MODE_PRIVATE)
        val auto = prefs.getBoolean("automatic", true); val wifi = prefs.getBoolean("wifi", true)
        UpdateManager.initialize(context)
        try {
            UpdateManager.options(false, false)
            val scheduler = context.getSystemService(JobScheduler::class.java)
            assertNull(scheduler.getPendingJob(6106))
            UpdateManager.options(true, true)
            val job = scheduler.getPendingJob(6106)
            assertNotNull(job)
            assertEquals(24 * 60 * 60 * 1000L, job!!.intervalMillis)
            assertEquals(UpdateJobService::class.java.name, job.service.className)
            assertTrue(job.isPersisted)
            assertTrue(UpdateManager.state.value.automatic)
        } finally { UpdateManager.options(auto, wifi) }
    }

    @Test fun foreignInstallerStatusCannotChangeUpdateState() {
        UpdateManager.initialize(context)
        UpdateManager.cancel()
        waitFor { UpdateManager.isInitializedReady && !UpdateManager.state.value.busy }
        val before = UpdateManager.state.value
        UpdateManager.installerResultWhenReady(Intent().putExtra(PackageInstaller.EXTRA_SESSION_ID, -200)
            .putExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_SUCCESS))
        Thread.sleep(250)
        assertEquals(before, UpdateManager.state.value)
    }

    @Test fun installerReceiverAndJobArePermissionProtected() {
        val receiver = context.packageManager.getReceiverInfo(android.content.ComponentName(context, UpdateInstallReceiver::class.java), 0)
        assertFalse(receiver.exported)
        val service = context.packageManager.getServiceInfo(android.content.ComponentName(context, UpdateJobService::class.java), 0)
        assertEquals("android.permission.BIND_JOB_SERVICE", service.permission)
    }

    @Test fun installedVersionCannotBeInstalledAgain() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("updateExactArtifact") == "1")
        UpdateManager.initialize(context)
        val folder = context.getExternalFilesDir("update-test")!!
        val signed = AndroidUpdateProtocol.verify(File(folder, "manifest.json").readBytes())
        assertEquals(BuildConfig.VERSION_CODE.toLong(), signed.versionCode)
        var rejected = false
        try { UpdateManager.validateApk(File(folder, "app.apk"), signed) } catch (_: Exception) { rejected = true }
        assertTrue("SAME_VERSION_MUST_NOT_INSTALL", rejected)
        emit("update-same-version-rejected", JSONObject().put("sameVersionRejected", true).put("versionCode", signed.versionCode))
    }

    @Test fun stalePartialIsRemovedAfterProcessRestart() {
        val phase = InstrumentationRegistry.getArguments().getString("updatePartialPhase")
        assumeTrue(phase == "prepare" || phase == "verify")
        val part = File(context.noBackupFilesDir, "updates/tg-update-process-test.part")
        if (phase == "prepare") {
            part.parentFile!!.mkdirs()
            part.writeText("INCOMPLETE-APK-FIXTURE")
            assertTrue(part.isFile)
        } else {
            UpdateManager.initialize(context)
            waitFor { UpdateManager.isInitializedReady }
            assertFalse("COLD_START_LEFT_PARTIAL", part.exists())
            emit("update-partial-cleanup", JSONObject().put("partialRemoved", true).put("api", Build.VERSION.SDK_INT))
        }
    }

    @Test fun liveOfferAndVerifiedDownload() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("updateLiveProbe") == "1")
        // This test belongs only to an isolated PRIVATE lower-version updater fixture.
        assertTrue("PRIVATE_CLIENT_REQUIRED", context.packageManager.getPackageInfo(context.packageName, 0).versionName.orEmpty().contains("update-test"))
        val auto = InstrumentationRegistry.getArguments().getString("updateLiveAuto") == "1"
        val prefs = context.getSharedPreferences("verified_updates", Context.MODE_PRIVATE)
        // Freeze only this private fixture's updater before restoration can schedule work.
        assertTrue(prefs.edit().putBoolean("automatic", false).putBoolean("wifi", false).commit())
        val jobs = context.getSystemService(JobScheduler::class.java)
        jobs.cancel(6106); jobs.cancel(6108)
        UpdateManager.initialize(context)
        UpdateManager.options(false, false)
        UpdateManager.cancel()
        val busyField = UpdateManager::class.java.getDeclaredField("busy").apply { isAccessible = true }
        waitFor(25000) {
            UpdateManager.isInitializedReady && !(busyField.get(UpdateManager) as AtomicBoolean).get()
        }
        assertFalse("INSTALLER_MUST_BE_IDLE", UpdateManager.state.value.phase in setOf(UpdatePhase.INSTALLING, UpdatePhase.CONFIRM))
        assertTrue("INSTALL_SESSION_MUST_BE_IDLE", prefs.getInt("session", -1) < 0)
        val floor = prefs.getLong("highest_code", 0)
        val floorHash = prefs.getString("highest_hash", null)
        // Invoke only our own cache cleanup while idle. It also clears in-memory manifest/SHA,
        // so an old READY state cannot supply a cached download to this run.
        UpdateManager::class.java.getDeclaredMethod("cleanupFiles").apply { isAccessible = true }.invoke(UpdateManager)
        assertEquals(floor, prefs.getLong("highest_code", 0))
        assertEquals(floorHash, prefs.getString("highest_hash", null))
        val cache = File(context.noBackupFilesDir.canonicalFile, "updates")
        assertFalse(File(cache, "verified.apk").exists())
        assertFalse(File(cache, "manifest.json").exists())
        assertFalse(cache.listFiles().orEmpty().any { it.name.startsWith("tg-update-") && it.name.endsWith(".part") })
        assertTrue(prefs.edit().putLong("attempted", 0).putLong("checked", 0).putLong("download_attempt", 0).commit())
        emit("update-live-fresh-cache", JSONObject().put("api", Build.VERSION.SDK_INT)
            .put("updaterCacheClearedWhileIdle", true).put("rollbackFloorPreserved", true)
            .put("proxyProfileTouched", false).put("privateFixture", true))
        val phases = CopyOnWriteArraySet<String>()
        val intermediate = AtomicBoolean(false)
        val operationStarted = AtomicBoolean(false)
        val observerScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        observerScope.launch(start = CoroutineStart.UNDISPATCHED) {
            UpdateManager.state.collect {
                phases.add(it.phase.name)
                if (it.phase in setOf(UpdatePhase.CHECKING, UpdatePhase.DOWNLOADING, UpdatePhase.VERIFYING)) operationStarted.set(true)
                if (operationStarted.get() && it.phase == UpdatePhase.DOWNLOADING && it.bytes > 0 && it.bytes < it.total) intermediate.set(true)
            }
        }
        try {
            UpdateManager.options(auto, auto)
            ActivityScenario.launch(MainActivity::class.java).use {
                if (auto) UpdateManager.foreground() else {
                    var accepted = false
                    val checked = AtomicBoolean(false)
                    waitFor { if (!accepted) accepted = UpdateManager.check(true, done = { checked.set(true) }); accepted }
                    // A restored AVAILABLE state predates this check. Await this invocation's
                    // completion, rather than mistaking an old state for its result.
                    waitFor(25000) { checked.get() }
                    emitUpdateState("update-live-offer-state", auto, phases)
                    assertEquals(UpdatePhase.AVAILABLE, UpdateManager.state.value.phase)
                    UpdateManager.download()
                }
                waitFor(200000) {
                    operationStarted.get() && (UpdateManager.state.value.phase == UpdatePhase.ERROR ||
                        UpdateManager.state.value.phase == UpdatePhase.READY && "DOWNLOADING" in phases && intermediate.get())
                }
                emitUpdateState("update-live-download-state", auto, phases)
                assertEquals(UpdatePhase.READY, UpdateManager.state.value.phase)
                assertTrue("UPDATE_DOWNLOAD_PHASE_MISSING", "DOWNLOADING" in phases)
                assertTrue("UPDATE_REAL_PROGRESS_MISSING", intermediate.get())
                emit("update-live-ready", JSONObject().put("offeredVersion", UpdateManager.state.value.version)
                    .put("verifiedReady", true).put("realIntermediateProgress", intermediate.get())
                    .put("phases", phases.joinToString(",")).put("automatic", auto)
                    .put("api", Build.VERSION.SDK_INT).put("privateFixture", true).put("installedAutomatically", false))
            }
        } finally { observerScope.cancel() }
    }

    @Test fun directVerifiedTransportProbe() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("updateDirectTransportProbe") == "1")
        assertTrue("PRIVATE_CLIENT_REQUIRED", context.packageManager.getPackageInfo(context.packageName, 0)
            .versionName.orEmpty().contains("update-test"))
        val parent = context.noBackupFilesDir.canonicalFile
        val destination = File(parent, "update-transport-probe-${java.util.UUID.randomUUID()}.apk")
        assertEquals(parent, destination.canonicalFile.parentFile)
        assertFalse(destination.exists())
        var received = 0L
        var total = 0L
        var stage = "metadata"
        var outcome = "not_started"
        var failureCode = "none"
        var removed = false
        val started = System.nanoTime()
        try {
            val transport = HttpsUpdateTransport()
            val candidate = AndroidUpdateProtocol.verify(transport.fetchManifest())
            total = candidate.size
            stage = "download"
            transport.download(candidate, destination, progress = { bytes, size -> received = bytes; total = size })
            stage = "verified"
            outcome = "success"
        } catch (error: Exception) {
            outcome = "failure"
            // Deliberately omit messages, URLs, paths and remote response contents.
            failureCode = if (error is UpdateException) error.code.name else error.javaClass.simpleName
        } finally {
            removed = !destination.exists() || destination.delete()
            emit("update-direct-transport-probe", JSONObject().put("api", Build.VERSION.SDK_INT)
                .put("stage", stage).put("outcome", outcome).put("failureCode", failureCode)
                .put("bytes", received).put("total", total)
                .put("elapsedMs", (System.nanoTime() - started) / 1_000_000)
                .put("ownedProbeRemoved", removed).put("privateFixture", true))
        }
        assertTrue("OWNED_PROBE_CLEANUP_FAILED", removed)
        assertEquals("DIRECT_UPDATE_TRANSPORT_$failureCode", "success", outcome)
    }

    @Test fun platformVerifiedHttpsProbe() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("updatePlatformHttpsProbe") == "1")
        assertTrue("PRIVATE_CLIENT_REQUIRED", context.packageManager.getPackageInfo(context.packageName, 0)
            .versionName.orEmpty().contains("update-test"))
        var connection: HttpsURLConnection? = null
        var bytes = 0L
        var total = 0L
        var outcome = "not_started"
        var stage = "metadata"
        var cipher = "unknown"
        var failure: Exception? = null
        val started = System.nanoTime()
        val watchdog = Executors.newSingleThreadScheduledExecutor { action ->
            Thread(action, "private-update-https-probe").apply { isDaemon = true }
        }
        val deadline = started + TimeUnit.SECONDS.toNanos(180)
        try {
            val candidate = AndroidUpdateProtocol.verify(HttpsUpdateTransport().fetchManifest())
            total = candidate.size
            // Only the signed immutable update path on the compiled origin is used.
            val current = URL(HttpsUpdateTransport.ORIGIN + candidate.apkPath).openConnection() as HttpsURLConnection
            connection = current
            current.instanceFollowRedirects = false
            current.useCaches = false
            current.connectTimeout = 10_000
            current.readTimeout = 10_000
            current.setRequestProperty("Accept-Encoding", "identity")
            current.setRequestProperty("Connection", "close")
            watchdog.schedule({ current.disconnect() }, 180, TimeUnit.SECONDS)
            stage = "headers"
            check(current.responseCode == 200) { "UNEXPECTED_HTTP_STATUS" }
            check(current.contentLengthLong == total) { "UNEXPECTED_CONTENT_LENGTH" }
            check(current.contentEncoding == null || current.contentEncoding.equals("identity", ignoreCase = true)) {
                "UNEXPECTED_CONTENT_ENCODING"
            }
            cipher = current.cipherSuite
            val digest = MessageDigest.getInstance("SHA-256")
            stage = "download"
            current.inputStream.use { input ->
                val buffer = ByteArray(65_536)
                while (bytes < total) {
                    check(System.nanoTime() < deadline) { "TOTAL_DEADLINE_EXCEEDED" }
                    val count = input.read(buffer, 0, minOf(buffer.size.toLong(), total - bytes).toInt())
                    check(count >= 0) { "EARLY_EOF" }
                    if (count == 0) continue
                    digest.update(buffer, 0, count)
                    bytes += count
                }
            }
            stage = "hash"
            check(digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) } == candidate.sha256) { "HASH_MISMATCH" }
            outcome = "success"
            stage = "verified"
        } catch (error: Exception) {
            outcome = "failure"
            failure = error
        } finally {
            connection?.disconnect()
            watchdog.shutdownNow()
            fun safeMessage(value: Throwable): String = value.message.orEmpty()
                .replace(Regex("https?://[^\\s]+"), "<update-url>")
                .filter { it.code in 32..126 }.take(500)
            val causes = org.json.JSONArray()
            var cause: Throwable? = failure
            repeat(4) {
                cause?.let { value ->
                    causes.put(JSONObject().put("type", value.javaClass.name).put("message", safeMessage(value)))
                    cause = value.cause?.takeIf { it !== value }
                }
            }
            emit("update-platform-https-probe", JSONObject().put("api", Build.VERSION.SDK_INT)
                .put("outcome", outcome).put("stage", stage).put("bytes", bytes).put("total", total)
                .put("cipher", cipher).put("exceptions", causes)
                .put("elapsedMs", (System.nanoTime() - started) / 1_000_000)
                .put("privateFixture", true).put("defaultPlatformTrust", true).put("redirectsAllowed", false))
        }
        assertEquals("PLATFORM_UPDATE_TRANSPORT_FAILED", "success", outcome)
    }

    @Test fun capturedRawTlsProbe() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("updateCapturedRawTlsProbe") == "1")
        assertTrue("PRIVATE_CLIENT_REQUIRED", context.packageManager.getPackageInfo(context.packageName, 0)
            .versionName.orEmpty().contains("update-test"))
        val buffered = InstrumentationRegistry.getArguments().getString("updateRawBuffered") == "1"
        val aeadOnly = InstrumentationRegistry.getArguments().getString("updateRawAeadOnly") == "1"
        val smallArray = InstrumentationRegistry.getArguments().getString("updateRawSmallArray") == "1"
        val readLimit = InstrumentationRegistry.getArguments().getString("updateRawReadLimit")?.toInt() ?: 0
        require(readLimit in setOf(0, 8192, 16384)) { "UNSUPPORTED_TEST_READ_LIMIT" }
        val readFailure = AtomicReference<Throwable?>(null)
        val negotiated = AtomicReference<CapturedTlsSession?>(null)
        val factory = CapturingSslFactory(SSLContext.getDefault().socketFactory, readFailure, buffered, aeadOnly, negotiated, readLimit, smallArray)
        // Reflection targets our own internal fixture constructor, never a hidden Android API.
        val constructor = HttpsUpdateTransport::class.java.getDeclaredConstructor(String::class.java,
            SSLSocketFactory::class.java, Int::class.javaPrimitiveType!!, Int::class.javaPrimitiveType!!)
        constructor.isAccessible = true
        val transport = constructor.newInstance(HttpsUpdateTransport.ORIGIN, factory, 15_000, 180_000) as HttpsUpdateTransport
        val parent = context.noBackupFilesDir.canonicalFile
        val destination = File(parent, "update-raw-probe-${java.util.UUID.randomUUID()}.apk")
        assertEquals(parent, destination.canonicalFile.parentFile)
        assertFalse(destination.exists())
        var bytes = 0L
        var total = 0L
        var outcome = "not_started"
        var failureCode = "none"
        var removed = false
        val started = System.nanoTime()
        try {
            val candidate = AndroidUpdateProtocol.verify(HttpsUpdateTransport().fetchManifest())
            total = candidate.size
            transport.download(candidate, destination, progress = { received, size -> bytes = received; total = size })
            outcome = "success"
        } catch (error: Exception) {
            outcome = "failure"
            failureCode = if (error is UpdateException) error.code.name else error.javaClass.name
        } finally {
            removed = !destination.exists() || destination.delete()
            val causes = org.json.JSONArray()
            var cause: Throwable? = readFailure.get()
            repeat(4) {
                cause?.let { value ->
                    val message = value.message.orEmpty().replace(Regex("https?://[^\\s]+"), "<update-url>")
                        .filter { it.code in 32..126 }.take(700)
                    causes.put(JSONObject().put("type", value.javaClass.name).put("message", message))
                    cause = value.cause?.takeIf { it !== value }
                }
            }
            emit("update-captured-raw-tls-probe", JSONObject().put("api", Build.VERSION.SDK_INT)
                .put("outcome", outcome).put("failureCode", failureCode).put("exceptions", causes)
                .put("bytes", bytes).put("total", total).put("bufferedInput", buffered)
                .put("nativeReadLimit", readLimit)
                .put("smallNativeArray", smallArray)
                .put("aeadOnly", aeadOnly).put("negotiatedCipher", negotiated.get()?.cipher ?: "unknown")
                .put("negotiatedProtocol", negotiated.get()?.protocol ?: "unknown")
                .put("platformSocketClass", negotiated.get()?.socketClass ?: "unknown")
                .put("elapsedMs", (System.nanoTime() - started) / 1_000_000)
                .put("ownedProbeRemoved", removed).put("privateFixture", true)
                .put("defaultPlatformTrust", true).put("hostnameVerificationDelegated", true))
        }
        assertTrue("OWNED_RAW_PROBE_CLEANUP_FAILED", removed)
        assertEquals("RAW_UPDATE_TRANSPORT_$failureCode", "success", outcome)
    }
}

/** Transparent test-only observation. The real platform socket still owns all TLS decisions. */
private data class CapturedTlsSession(val cipher: String, val protocol: String, val socketClass: String)

private class CapturingSslFactory(
    private val original: SSLSocketFactory,
    private val failure: AtomicReference<Throwable?>,
    private val buffered: Boolean,
    private val aeadOnly: Boolean,
    private val negotiated: AtomicReference<CapturedTlsSession?>,
    private val readLimit: Int,
    private val smallArray: Boolean,
) : SSLSocketFactory() {
    private fun wrap(socket: Socket): Socket = CapturingSslSocket(socket as SSLSocket, failure, buffered, aeadOnly, negotiated, readLimit, smallArray)
    override fun getDefaultCipherSuites(): Array<String> = original.defaultCipherSuites
    override fun getSupportedCipherSuites(): Array<String> = original.supportedCipherSuites
    override fun createSocket(socket: Socket, host: String, port: Int, close: Boolean): Socket = wrap(original.createSocket(socket, host, port, close))
    override fun createSocket(host: String, port: Int): Socket = wrap(original.createSocket(host, port))
    override fun createSocket(host: String, port: Int, local: InetAddress, localPort: Int): Socket = wrap(original.createSocket(host, port, local, localPort))
    override fun createSocket(host: InetAddress, port: Int): Socket = wrap(original.createSocket(host, port))
    override fun createSocket(host: InetAddress, port: Int, local: InetAddress, localPort: Int): Socket = wrap(original.createSocket(host, port, local, localPort))
}

private class CapturingSslSocket(
    private val original: SSLSocket,
    private val failure: AtomicReference<Throwable?>,
    private val buffered: Boolean,
    private val aeadOnly: Boolean,
    private val negotiated: AtomicReference<CapturedTlsSession?>,
    private val readLimit: Int,
    private val smallArray: Boolean,
) : SSLSocket() {
    override fun getInputStream(): InputStream {
        val scratch = if (smallArray) ByteArray(8192) else null
        val observed = object : FilterInputStream(original.inputStream) {
            override fun read(): Int = try { `in`.read() } catch (error: Exception) { failure.compareAndSet(null, error); throw error }
            override fun read(bytes: ByteArray, offset: Int, length: Int): Int = try {
                val countLimit = if (readLimit > 0) minOf(length, readLimit) else length
                if (scratch != null) {
                    val count = `in`.read(scratch, 0, minOf(countLimit, scratch.size))
                    if (count > 0) scratch.copyInto(bytes, offset, 0, count)
                    count
                } else `in`.read(bytes, offset, countLimit)
            }
                catch (error: Exception) { failure.compareAndSet(null, error); throw error }
        }
        return if (buffered) BufferedInputStream(observed, 8192) else observed
    }
    override fun getOutputStream() = original.outputStream
    override fun close() = original.close()
    override fun isClosed() = original.isClosed
    override fun getSoTimeout() = original.soTimeout
    override fun setSoTimeout(value: Int) { original.soTimeout = value }
    override fun getSSLParameters(): SSLParameters = original.sslParameters
    override fun setSSLParameters(value: SSLParameters) { original.sslParameters = value }
    override fun getSupportedCipherSuites(): Array<String> = original.supportedCipherSuites
    override fun getEnabledCipherSuites(): Array<String> = original.enabledCipherSuites
    override fun setEnabledCipherSuites(value: Array<String>) { original.enabledCipherSuites = value }
    override fun getSupportedProtocols(): Array<String> = original.supportedProtocols
    override fun getEnabledProtocols(): Array<String> = original.enabledProtocols
    override fun setEnabledProtocols(value: Array<String>) { original.enabledProtocols = value }
    override fun getSession(): SSLSession = original.session
    override fun addHandshakeCompletedListener(value: HandshakeCompletedListener) = original.addHandshakeCompletedListener(value)
    override fun removeHandshakeCompletedListener(value: HandshakeCompletedListener) = original.removeHandshakeCompletedListener(value)
    override fun startHandshake() {
        if (aeadOnly) {
            // A diagnostic restriction of already-enabled suites; never enables older ciphers or relaxes trust.
            val enabled = original.enabledCipherSuites.filter { "_GCM_" in it || "CHACHA20" in it }.toTypedArray()
            check(enabled.isNotEmpty()) { "NO_ENABLED_AEAD_CIPHERS" }
            original.enabledCipherSuites = enabled
        }
        original.startHandshake()
        val session = original.session
        negotiated.set(CapturedTlsSession(session.cipherSuite, session.protocol, original.javaClass.name))
    }
    override fun setUseClientMode(value: Boolean) { original.useClientMode = value }
    override fun getUseClientMode() = original.useClientMode
    override fun setNeedClientAuth(value: Boolean) { original.needClientAuth = value }
    override fun getNeedClientAuth() = original.needClientAuth
    override fun setWantClientAuth(value: Boolean) { original.wantClientAuth = value }
    override fun getWantClientAuth() = original.wantClientAuth
    override fun setEnableSessionCreation(value: Boolean) { original.enableSessionCreation = value }
    override fun getEnableSessionCreation() = original.enableSessionCreation
}
