package io.github.byshadow64.tgproxy

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import androidx.core.app.NotificationCompat
import io.github.byshadow64.tgproxy.core.AndroidUpdateManifest
import io.github.byshadow64.tgproxy.core.AndroidUpdateProtocol
import io.github.byshadow64.tgproxy.core.HttpsUpdateTransport
import io.github.byshadow64.tgproxy.core.UpdateException
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean

enum class UpdatePhase { IDLE, CHECKING, CURRENT, AVAILABLE, DOWNLOADING, VERIFYING, READY, INSTALLING, CONFIRM, ERROR }
data class UpdateUiState(
    val phase: UpdatePhase = UpdatePhase.IDLE,
    val version: String = "", val notes: String = "", val bytes: Long = 0, val total: Long = 0,
    val automatic: Boolean = true, val wifiDownload: Boolean = true,
    val errorRes: Int = 0, val lastChecked: Long = 0,
) {
    val busy get() = phase in setOf(UpdatePhase.CHECKING, UpdatePhase.DOWNLOADING, UpdatePhase.VERIFYING, UpdatePhase.INSTALLING)
}

/** Pure decisions shared by foreground and scheduled work; clock correction must not disable checks forever. */
internal object UpdatePolicy {
    const val DAY = 24 * 60 * 60 * 1000L
    const val RETRY = 30 * 60 * 1000L
    fun elapsed(now: Long, previous: Long, interval: Long): Boolean =
        previous <= 0 || now < previous || now - previous >= interval
    fun automaticCheckDue(now: Long, checked: Long, attempted: Long): Boolean =
        elapsed(now, checked, DAY) && elapsed(now, attempted, RETRY)
    fun retryDelay(now: Long, attempted: Long): Long =
        if (elapsed(now, attempted, RETRY)) 0 else RETRY - (now - attempted)
    fun acceptsVersion(code: Long, hash: String, highestCode: Long, highestHash: String?): Boolean =
        highestCode >= 0 && code >= highestCode &&
            (highestCode == 0L || code > highestCode || hash == highestHash)
}

/** Separate from the proxy profile/lifecycle. Only authenticated public update metadata is persisted. */
object UpdateManager {
    private const val JOB_ID = 6106
    internal const val DOWNLOAD_JOB_ID = 6108
    private const val NOTIFICATION_ID = 6107
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutable = MutableStateFlow(UpdateUiState())
    val state = mutable.asStateFlow()
    private lateinit var context: Context
    private val initializedReady = CompletableDeferred<Unit>()
    internal val isInitializedReady get() = initializedReady.isCompleted
    private val busy = AtomicBoolean(false)
    @Volatile private var cancel: AtomicBoolean? = null
    @Volatile private var owner: String? = null
    @Volatile private var manifest: AndroidUpdateManifest? = null
    @Volatile private var verifiedApkSha: String? = null
    @Volatile private var installerActive = false
    private var confirmation: Intent? = null
    private val preferences get() = context.getSharedPreferences("verified_updates", Context.MODE_PRIVATE)
    // Android's credential-encrypted path may contain an alias; the transport requires a canonical parent.
    private val directory get(): File {
        val parent = context.noBackupFilesDir.canonicalFile
        val target = File(parent, "updates")
        kotlin.check(!java.nio.file.Files.isSymbolicLink(target.toPath()))
        kotlin.check(target.isDirectory || target.mkdirs())
        return target.canonicalFile.also { kotlin.check(it.parentFile == parent) }
    }
    private val apk get() = File(directory, "verified.apk")
    private val metadata get() = File(directory, "manifest.json")
    private val transport = HttpsUpdateTransport()

    @Synchronized fun initialize(value: Context, incomingSession: Int? = null) {
        if (::context.isInitialized) return
        context = value.applicationContext
        mutable.value = UpdateUiState(automatic = preferences.getBoolean("automatic", true),
            wifiDownload = preferences.getBoolean("wifi", true), lastChecked = preferences.getLong("checked", 0))
        context.getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel("updates", context.getString(R.string.update_title), NotificationManager.IMPORTANCE_DEFAULT))
        schedule()
        launchTask("restore", done = { initializedReady.complete(Unit) }, allowInstalling = true) { token ->
            try {
                // A cold receiver may be delivering a committed session's result. Keep only its matching record.
                reconcileSessions(incomingSession)
                // No transfer exists in a newly created process; remove partials left by process death.
                clearPartialFiles()
                if (metadata.isFile && metadata.length() in 1..AndroidUpdateProtocol.MAX_METADATA_BYTES.toLong()) {
                    val candidate = AndroidUpdateProtocol.verify(metadata.readBytes())
                    acceptVersion(candidate)
                    if (candidate.versionCode > installedCode() && candidate.minSdk <= Build.VERSION.SDK_INT) {
                        manifest = candidate
                        show(candidate, UpdatePhase.AVAILABLE)
                        if (apk.isFile) {
                            validateApk(apk, candidate, token)
                            verifiedApkSha = candidate.sha256
                            show(candidate, UpdatePhase.READY)
                        }
                    } else {
                        cleanupFiles()
                        mutable.update { it.copy(phase = UpdatePhase.CURRENT) }
                    }
                } else cleanupFiles()
                if (installerActive) mutable.update { it.copy(phase = UpdatePhase.INSTALLING) }
            } catch (_: Exception) {
                runCatching { cleanupFiles() }
                mutable.update { it.copy(phase = UpdatePhase.ERROR, errorRes = R.string.update_verification_error) }
            }
        }
    }

    fun foreground() {
        if (!::context.isInitialized) return
        scope.launch {
            initializedReady.await()
            if (!state.value.automatic || installing()) return@launch
            if (canAutoDownload()) downloadAutomatic(AtomicBoolean(false))
            else if (automaticCheckDue()) check(false)
            schedulePendingDownload()
        }
    }

    fun options(automatic: Boolean, wifi: Boolean) {
        preferences.edit().putBoolean("automatic", automatic).putBoolean("wifi", wifi).apply()
        mutable.update { it.copy(automatic = automatic, wifiDownload = wifi) }
        if (!automatic && owner?.startsWith("automatic") == true) cancel?.set(true)
        if (!wifi && owner == "automatic-download") cancel?.set(true)
        schedule()
        scope.launch {
            initializedReady.await()
            schedulePendingDownload()
            if (canAutoDownload()) downloadAutomatic(AtomicBoolean(false))
        }
    }

    private fun schedule() {
        val scheduler = context.getSystemService(JobScheduler::class.java)
        if (!state.value.automatic) { scheduler.cancel(JOB_ID); scheduler.cancel(DOWNLOAD_JOB_ID); return }
        if (scheduler.getPendingJob(JOB_ID) == null) {
            scheduler.schedule(JobInfo.Builder(JOB_ID, ComponentName(context, UpdateJobService::class.java))
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY).setRequiresBatteryNotLow(true)
                .setPeriodic(UpdatePolicy.DAY).setPersisted(true).build())
        }
    }

    /** One pending download job waits for an unmetered network; it does not poll unavailable networks. */
    private fun schedulePendingDownload() {
        if (!initializedReady.isCompleted) return
        val scheduler = context.getSystemService(JobScheduler::class.java)
        if (!state.value.automatic || !state.value.wifiDownload || manifest == null || hasVerifiedApk() || installing()) {
            scheduler.cancel(DOWNLOAD_JOB_ID)
            return
        }
        if (busy.get() || scheduler.getPendingJob(DOWNLOAD_JOB_ID) != null) return
        val delay = UpdatePolicy.retryDelay(System.currentTimeMillis(), preferences.getLong("download_attempt", 0))
        scheduler.schedule(JobInfo.Builder(DOWNLOAD_JOB_ID, ComponentName(context, UpdateJobService::class.java))
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_UNMETERED).setRequiresBatteryNotLow(true)
            .setMinimumLatency(delay).setPersisted(true).build())
    }

    /** The JobService owns this token even while the controller is still restoring. */
    fun background(token: AtomicBoolean, downloadOnly: Boolean, done: () -> Unit) {
        scope.launch {
            initializedReady.await()
            if (token.get() || !state.value.automatic || installing()) { done(); return@launch }
            val started = if (downloadOnly || canAutoDownload()) {
                if (canAutoDownload()) downloadAutomatic(token, done) else false
            } else if (automaticCheckDue()) check(false, done, token) else false
            if (!started) done()
        }
    }

    fun cancelBackground() { if (owner?.startsWith("automatic") == true) cancel?.set(true) }
    fun cancel() { cancel?.set(true) }

    private fun installing() = installerActive || state.value.phase in setOf(UpdatePhase.INSTALLING, UpdatePhase.CONFIRM)
    private fun automaticCheckDue() = UpdatePolicy.automaticCheckDue(System.currentTimeMillis(),
        preferences.getLong("checked", 0), preferences.getLong("attempted", 0))
    private fun canAutoDownload(): Boolean = state.value.automatic && state.value.wifiDownload &&
        manifest != null && !hasVerifiedApk() && !installing() && wifiUnmetered() &&
        UpdatePolicy.elapsed(System.currentTimeMillis(), preferences.getLong("download_attempt", 0), UpdatePolicy.RETRY)

    private fun launchTask(
        source: String,
        done: () -> Unit = {},
        token: AtomicBoolean = AtomicBoolean(false),
        allowInstalling: Boolean = false,
        block: suspend (AtomicBoolean) -> Unit,
    ): Boolean {
        if (token.get() || !allowInstalling && installing() || !busy.compareAndSet(false, true)) return false
        cancel = token; owner = source
        scope.launch {
            try { block(token) }
            finally {
                cancel = null; owner = null; busy.set(false)
                try { done() } finally { schedulePendingDownload() }
            }
        }
        return true
    }

    fun check(manual: Boolean = true, done: () -> Unit = {}, token: AtomicBoolean = AtomicBoolean(false)): Boolean {
        if (!initializedReady.isCompleted || !manual && (!state.value.automatic || !automaticCheckDue())) return false
        return launchTask(if (manual) "manual" else "automatic-check", done, token) { cancellation ->
            mutable.update { it.copy(phase = UpdatePhase.CHECKING, errorRes = 0) }
            try {
                kotlin.check(preferences.edit().putLong("attempted", System.currentTimeMillis()).commit())
                val candidate = AndroidUpdateProtocol.verify(transport.fetchManifest {
                    if (!manual && !state.value.automatic) cancellation.set(true)
                    cancellation.get()
                })
                kotlin.check(!cancellation.get())
                require(candidate.minSdk <= Build.VERSION.SDK_INT)
                acceptVersion(candidate)
                val now = System.currentTimeMillis()
                kotlin.check(preferences.edit().putLong("checked", now).commit())
                mutable.update { it.copy(lastChecked = now) }
                if (candidate.versionCode <= installedCode()) {
                    cleanupFiles()
                    mutable.update { it.copy(phase = UpdatePhase.CURRENT, version = "", notes = "", bytes = 0, total = 0) }
                } else {
                    val previous = manifest
                    if (previous?.sha256 != candidate.sha256) discardApk()
                    val temp = File(directory, "manifest.tmp")
                    temp.writeBytes(candidate.encoded())
                    kotlin.check(temp.renameTo(metadata))
                    manifest = candidate
                    show(candidate, UpdatePhase.AVAILABLE)
                    if (apk.isFile) {
                        try {
                            validateApk(apk, candidate, cancellation)
                            verifiedApkSha = candidate.sha256
                            show(candidate, UpdatePhase.READY)
                        } catch (error: Exception) { discardApk(); throw error }
                    } else if (canAutoDownload()) fetch(candidate, cancellation, automatic = true)
                    notifyAvailable()
                }
            } catch (error: Exception) { failure(error, cancellation) }
        }
    }

    fun download() {
        if (!initializedReady.isCompleted) return
        val candidate = manifest ?: return
        launchTask("manual") { token ->
            try { fetch(candidate, token, automatic = false); notifyAvailable() }
            catch (error: Exception) { failure(error, token) }
        }
    }

    private fun downloadAutomatic(token: AtomicBoolean, done: () -> Unit = {}): Boolean {
        val candidate = manifest ?: return false
        if (!canAutoDownload()) return false
        return launchTask("automatic-download", done, token) { cancellation ->
            try { fetch(candidate, cancellation, automatic = true); notifyAvailable() }
            catch (error: Exception) { failure(error, cancellation) }
        }
    }

    private fun fetch(candidate: AndroidUpdateManifest, token: AtomicBoolean, automatic: Boolean) {
        require(candidate.versionCode > installedCode())
        acceptVersion(candidate)
        if (apk.isFile) {
            try {
                validateApk(apk, candidate, token)
                verifiedApkSha = candidate.sha256
                show(candidate, UpdatePhase.READY)
                return
            } catch (error: Exception) {
                discardApk()
                if (token.get()) throw error
            }
        }
        verifiedApkSha = null
        kotlin.check(preferences.edit().putLong("download_attempt", System.currentTimeMillis()).commit())
        fun cancelled(): Boolean {
            if (automatic && (!state.value.automatic || !state.value.wifiDownload || !wifiUnmetered())) token.set(true)
            return token.get()
        }
        kotlin.check(!cancelled())
        mutable.update { it.copy(phase = UpdatePhase.DOWNLOADING, bytes = 0, total = candidate.size, errorRes = 0) }
        transport.download(candidate, apk, ::cancelled) { received, total ->
            mutable.update { it.copy(bytes = received, total = total) }
        }
        mutable.update { it.copy(phase = UpdatePhase.VERIFYING) }
        try {
            kotlin.check(!cancelled())
            validateApk(apk, candidate, token)
            verifiedApkSha = candidate.sha256
        } catch (error: Exception) { discardApk(); throw error }
        show(candidate, UpdatePhase.READY)
    }

    private fun acceptVersion(candidate: AndroidUpdateManifest) {
        val highest = preferences.getLong("highest_code", 0)
        val hash = preferences.getString("highest_hash", null)
        require(UpdatePolicy.acceptsVersion(candidate.versionCode, candidate.sha256, highest, hash))
        if (candidate.versionCode > highest) {
            kotlin.check(preferences.edit().putLong("highest_code", candidate.versionCode)
                .putString("highest_hash", candidate.sha256).commit())
        }
    }

    private fun hasVerifiedApk(): Boolean {
        val candidate = manifest ?: return false
        return verifiedApkSha == candidate.sha256 && apk.isFile && apk.length() == candidate.size
    }

    private fun show(candidate: AndroidUpdateManifest, phase: UpdatePhase) {
        val language = context.resources.configuration.locales[0].language
        mutable.update { it.copy(phase = phase, version = candidate.versionName,
            notes = if (language == "ru") candidate.notesRu else candidate.notesEn,
            bytes = if (phase == UpdatePhase.READY) candidate.size else 0, total = candidate.size, errorRes = 0) }
    }

    private fun failure(error: Exception, token: AtomicBoolean) {
        if (token.get()) {
            mutable.update { it.copy(phase = when {
                hasVerifiedApk() -> UpdatePhase.READY
                manifest != null -> UpdatePhase.AVAILABLE
                else -> UpdatePhase.IDLE
            }, bytes = 0, errorRes = 0) }
            return
        }
        val id = if (error is UpdateException && error.code.name in setOf("NETWORK", "HTTP", "TIMEOUT"))
            R.string.update_network_error else R.string.update_verification_error
        mutable.update { it.copy(phase = UpdatePhase.ERROR, errorRes = id) }
    }

    @Suppress("DEPRECATION")
    private fun packageInfo(file: File? = null): PackageInfo {
        val flags = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
        return if (file == null) context.packageManager.getPackageInfo(context.packageName, flags)
        else requireNotNull(context.packageManager.getPackageArchiveInfo(file.absolutePath, flags))
    }
    @Suppress("DEPRECATION") private fun code(info: PackageInfo) = if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()
    private fun installedCode() = code(packageInfo())
    @Suppress("DEPRECATION") private fun signers(info: PackageInfo): Set<String> {
        val values = if (Build.VERSION.SDK_INT >= 28) info.signingInfo?.apkContentsSigners else info.signatures
        return requireNotNull(values).map { digest(it.toByteArray()) }.toSet()
    }
    private fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }

    internal fun validateApk(file: File, candidate: AndroidUpdateManifest, token: AtomicBoolean = AtomicBoolean(false)) {
        require(file.isFile && file.length() == candidate.size)
        val hash = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(65536)
            while (true) { kotlin.check(!token.get()); val n = input.read(buffer); if (n < 0) break; hash.update(buffer, 0, n) }
        }
        require(hash.digest().joinToString("") { "%02x".format(it.toInt() and 255) } == candidate.sha256)
        val archive = packageInfo(file); val installed = packageInfo()
        require(archive.packageName == context.packageName && code(archive) == candidate.versionCode && code(archive) > code(installed))
        require(archive.versionName == candidate.versionName && archive.applicationInfo?.minSdkVersion == candidate.minSdk)
        val flags = requireNotNull(archive.applicationInfo).flags
        require(flags and (ApplicationInfo.FLAG_DEBUGGABLE or ApplicationInfo.FLAG_TEST_ONLY) == 0)
        require(signers(archive) == setOf(candidate.signerSha256) && signers(archive) == signers(installed))
    }

    /** Called only by an explicit Install click after Android's per-source permission. */
    fun install() {
        if (!initializedReady.isCompleted || installing() || !context.packageManager.canRequestPackageInstalls()) return
        val candidate = manifest ?: return
        if (state.value.phase !in setOf(UpdatePhase.READY, UpdatePhase.ERROR)) return
        launchTask("install") { token ->
            var sessionId: Int? = null
            try {
                reconcileSessions(null)
                mutable.update { it.copy(phase = UpdatePhase.VERIFYING, errorRes = 0) }
                validateApk(apk, candidate, token)
                verifiedApkSha = candidate.sha256
                val installer = context.packageManager.packageInstaller
                val parameters = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
                    setAppPackageName(context.packageName); setSize(candidate.size)
                    if (Build.VERSION.SDK_INT >= 31) setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_REQUIRED)
                }
                val newSession = installer.createSession(parameters)
                sessionId = newSession
                installer.openSession(newSession).use { session ->
                    session.openWrite("base.apk", 0, candidate.size).use { output ->
                        apk.inputStream().use { input ->
                            val buffer = ByteArray(65536)
                            while (true) { kotlin.check(!token.get()); val n = input.read(buffer); if (n < 0) break; output.write(buffer, 0, n) }
                        }
                        session.fsync(output)
                    }
                    kotlin.check(preferences.edit().putInt("session", newSession).commit())
                    installerActive = true
                    mutable.update { it.copy(phase = UpdatePhase.INSTALLING) }
                    val intent = Intent(context, UpdateInstallReceiver::class.java).setAction(context.packageName + ".UPDATE_RESULT")
                    val flags = PendingIntent.FLAG_UPDATE_CURRENT or (if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0)
                    session.commit(PendingIntent.getBroadcast(context, newSession, intent, flags).intentSender)
                }
            } catch (error: Exception) {
                sessionId?.let { abandonOwnedSession(it) }
                preferences.edit().remove("session").apply()
                installerActive = false
                failure(error, token)
            }
        }
    }

    /** Retain only a matching cold receiver result. Ordinary process recovery abandons orphaned own sessions. */
    private fun reconcileSessions(incomingSession: Int?) {
        val saved = preferences.getInt("session", -1)
        val keep = incomingSession?.takeIf { it >= 0 && it == saved }
        for (session in context.packageManager.packageInstaller.mySessions) {
            if (session.appPackageName == context.packageName && session.sessionId != keep) abandonOwnedSession(session.sessionId)
        }
        if (keep == null) {
            preferences.edit().remove("session").apply()
            installerActive = false
            synchronized(this) { confirmation = null }
        } else installerActive = true
    }

    private fun abandonOwnedSession(id: Int) {
        try {
            val installer = context.packageManager.packageInstaller
            if (installer.mySessions.any { it.sessionId == id && it.appPackageName == context.packageName }) installer.abandonSession(id)
        } catch (_: Exception) { /* Session can already have completed or been removed by Android. */ }
    }

    fun installerResultWhenReady(intent: Intent, done: () -> Unit = {}) {
        scope.launch {
            try {
                withTimeout(8_000) { initializedReady.await(); installerResult(intent) }
            } catch (_: CancellationException) {
                // The receiver must finish within its budget; startup reconciliation can clear an orphan.
            } catch (_: Exception) {
                val session = preferences.getInt("session", -1)
                if (session >= 0 && intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -2) == session) {
                    runCatching { finishFailedInstallation(session) }
                }
            } finally { done() }
        }
    }

    private fun installerResult(intent: Intent) {
        val session = preferences.getInt("session", -1)
        if (session < 0 || intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -2) != session) return
        when (intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                @Suppress("DEPRECATION") val next = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                if (next == null) { finishFailedInstallation(session); return }
                synchronized(this) { confirmation = next }
                installerActive = true
                mutable.update { it.copy(phase = UpdatePhase.CONFIRM) }
            }
            PackageInstaller.STATUS_SUCCESS -> {
                preferences.edit().remove("session").apply()
                installerActive = false
                synchronized(this) { confirmation = null }
                cleanupFiles()
                context.getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
                mutable.update { it.copy(phase = UpdatePhase.CURRENT, version = "", notes = "", bytes = 0, total = 0) }
            }
            else -> finishFailedInstallation(session)
        }
    }

    private fun finishFailedInstallation(session: Int) {
        abandonOwnedSession(session)
        preferences.edit().remove("session").apply()
        installerActive = false
        synchronized(this) { confirmation = null }
        mutable.update { it.copy(phase = if (hasVerifiedApk()) UpdatePhase.READY else UpdatePhase.ERROR,
            errorRes = R.string.update_install_error) }
    }

    @Synchronized fun takeConfirmation(): Intent? = confirmation.also { confirmation = null }
    fun confirmationUnavailable() {
        scope.launch {
            initializedReady.await()
            finishFailedInstallation(preferences.getInt("session", -1))
        }
    }

    private fun wifiUnmetered(): Boolean {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
    }

    private fun discardApk() { verifiedApkSha = null; apk.delete() }
    private fun cleanupFiles() {
        context.getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
        manifest = null; discardApk(); metadata.delete(); File(directory, "manifest.tmp").delete()
        clearPartialFiles()
    }
    private fun clearPartialFiles() {
        directory.listFiles()?.filter { it.isFile && it.name.startsWith("tg-update-") && it.name.endsWith(".part") }?.forEach { it.delete() }
    }

    private fun notifyAvailable() {
        val nm = context.getSystemService(NotificationManager::class.java)
        if (!nm.areNotificationsEnabled()) return
        val pending = PendingIntent.getActivity(context, NOTIFICATION_ID,
            Intent(context, MainActivity::class.java).putExtra("show_updates", true), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        try {
            nm.notify(NOTIFICATION_ID, NotificationCompat.Builder(context, "updates")
                .setSmallIcon(R.drawable.ic_proxy_notification).setContentTitle(context.getString(R.string.update_available, state.value.version))
                .setContentText(context.getString(if (state.value.phase == UpdatePhase.READY) R.string.update_ready else R.string.update_notification_available))
                .setContentIntent(pending).setAutoCancel(true).setOnlyAlertOnce(true).build())
        } catch (_: SecurityException) { /* Notification permission is optional; the in-app card remains. */ }
    }
}
