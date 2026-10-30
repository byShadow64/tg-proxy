package io.github.byshadow64.tgproxy

import android.Manifest
import android.app.ActivityManager
import android.app.Notification
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import androidx.core.content.ContextCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.byshadow64.tgproxy.core.HelperRegistryClient
import io.github.byshadow64.tgproxy.ui.PairingStatus
import io.github.byshadow64.tgproxy.ui.ProxyStatus
import io.github.byshadow64.tgproxy.ui.SshSetupPhase
import org.json.JSONObject
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.concurrent.TimeUnit

/**
 * Opt-in only: liveSshInputFile names a shell-readable /data/local/tmp/tgproxy-live-*.json.
 * Required keys: sshHost, sshPassword, expectedHostKeySha256, allowServerMutation=true,
 * allowRegisteredDevices=true. Optional: sshPort (22), sshUser (root),
 * allowExistingPrivateUpgrade (false), expectedHelperPinSha256, runAnonymousDataProbe (true).
 * The file is bounded and unlinked immediately after reading. No credential enters argv,
 * source, the main APK or receipts. This fixture does not roll back authorized server changes.
 */
@RunWith(AndroidJUnit4::class)
class LiveSshRuntimeInstrumentedTest {
    private class Input(val host: String, val port: Int, val password: CharArray, val hostKey: String,
        val allowPrivateUpgrade: Boolean, val expectedPin: String?, val dataProbe: Boolean)

    private fun checkSafe(condition: Boolean, code: String) = assertTrue(code, condition)

    private fun shellBytes(command: String, maximum: Int): ByteArray {
        val output = ByteArrayOutputStream()
        ParcelFileDescriptor.AutoCloseInputStream(
            InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(command)
        ).use { input ->
            val buffer = ByteArray(2048)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                checkSafe(output.size() + count <= maximum, "LIVE_SSH_PRIVATE_INPUT_TOO_LARGE")
                output.write(buffer, 0, count)
            }
        }
        return output.toByteArray()
    }

    private fun privateInput(path: String): Input {
        checkSafe(Regex("/data/local/tmp/tgproxy-live-[A-Za-z0-9_-]+[.]json").matches(path), "LIVE_SSH_INVALID_PRIVATE_PATH")
        val bytes = try { shellBytes("cat $path", 16 * 1024) }
        finally {
            val removal = shellBytes("rm -- $path", 1024)
            checkSafe(removal.isEmpty(), "LIVE_SSH_PRIVATE_INPUT_UNLINK_FAILED")
            removal.fill(0)
        }
        var privatePassword: CharArray? = null
        try {
            val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
            val json = JSONObject(text)
            val allowed = setOf("sshHost", "sshPort", "sshUser", "sshPassword", "expectedHostKeySha256",
                "allowServerMutation", "allowRegisteredDevices", "allowExistingPrivateUpgrade", "expectedHelperPinSha256", "runAnonymousDataProbe")
            checkSafe(json.keys().asSequence().all { it in allowed }, "LIVE_SSH_UNEXPECTED_PRIVATE_FIELD")
            checkSafe(json.get("allowServerMutation") == true && json.get("allowRegisteredDevices") == true,
                "LIVE_SSH_EXPLICIT_MUTATION_CONSENT_REQUIRED")
            val host = json.getString("sshHost")
            checkSafe(HelperRegistryClient.numericIp(host) == host, "LIVE_SSH_INVALID_ENDPOINT")
            val port = if (json.has("sshPort")) (json.get("sshPort") as Int) else 22
            checkSafe(port in 1..65535 && json.optString("sshUser", "root") == "root", "LIVE_SSH_ROOT_ENDPOINT_REQUIRED")
            val hostKey = json.getString("expectedHostKeySha256")
            checkSafe(Regex("SHA256:[A-Za-z0-9+/]{43}").matches(hostKey), "LIVE_SSH_EXPECTED_HOST_KEY_REQUIRED")
            val password = json.getString("sshPassword").toCharArray().also { privatePassword = it }
            json.remove("sshPassword")
            if (password.isEmpty() || password.size > 1024 || password.any { it == '\u0000' }) {
                password.fill('\u0000'); throw AssertionError("LIVE_SSH_INVALID_PASSWORD_INPUT")
            }
            val privateUpgrade = if (json.has("allowExistingPrivateUpgrade")) json.get("allowExistingPrivateUpgrade") as Boolean else false
            val dataProbe = if (json.has("runAnonymousDataProbe")) json.get("runAnonymousDataProbe") as Boolean else true
            val pin = if (json.has("expectedHelperPinSha256")) json.getString("expectedHelperPinSha256") else null
            if (pin != null && !Regex("[0-9a-f]{64}").matches(pin)) {
                password.fill('\u0000'); throw AssertionError("LIVE_SSH_INVALID_EXPECTED_HELPER_PIN")
            }
            return Input(host, port, password, hostKey, privateUpgrade, pin, dataProbe)
        } catch (failure: Throwable) {
            privatePassword?.fill('\u0000')
            if (failure is AssertionError && failure.message?.matches(Regex("LIVE_SSH_[A-Z0-9_]+")) == true) throw failure
            throw AssertionError("LIVE_SSH_INVALID_PRIVATE_INPUT")
        } finally { bytes.fill(0) }
    }

    @Suppress("DEPRECATION")
    private fun runningServices(context: Context) = context.getSystemService(ActivityManager::class.java).getRunningServices(Int.MAX_VALUE)
    private fun serviceExists(context: Context, type: Class<*>) = runningServices(context).any { it.service.className == type.name }
    private fun waitUntil(code: String, seconds: Long = 45, observe: () -> Unit = {}, condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds)
        while (System.nanoTime() < deadline) {
            observe()
            if (condition()) return
            Thread.sleep(25)
        }
        checkSafe(condition(), code)
    }

    @Test fun explicitSshSetupVerifiesHostKeyUsesPrivateFgsAndRestoresLocalProfile() {
        val path = InstrumentationRegistry.getArguments().getString("liveSshInputFile") ?: ""
        assumeTrue("Explicit private runtime file required", path.isNotEmpty())
        val input = privateInput(path)
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        var passwordCleared = false
        var foregroundSeen = false
        var notificationSeen = false
        var cancelActionSeen = false
        var hostKeyMatched = false
        var runtimeSuccess = false
        var leaseNotPersisted = false
        var realRoundTrip = false
        var listenerClosed = false
        var restored = false
        var safePhase = "NOT_STARTED"
        var failureCode: String? = null
        fun observeSetup() {
            if (runningServices(context).any { it.service.className == HelperSetupService::class.java.name && it.foreground }) foregroundSeen = true
            context.getSystemService(NotificationManager::class.java).activeNotifications
                .firstOrNull { it.id == HelperSetupService.NOTIFICATION_ID }?.notification?.let { notice ->
                    notificationSeen = notificationSeen || notice.flags and Notification.FLAG_ONGOING_EVENT != 0
                    cancelActionSeen = cancelActionSeen || notice.actions?.any {
                        it.title.toString() == context.getString(R.string.ui_cancel) && it.actionIntent != null
                    } == true
                }
            safePhase = AppRuntime.state.value.sshSetup.phase.name
        }
        try {
            if (Build.VERSION.SDK_INT >= 33) instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                scenario.onActivity {
                    AppRuntime.cancelHelperSsh(); it.stopService(Intent(it, HelperSetupService::class.java))
                    it.stopService(Intent(it, ProxyService::class.java))
                }
                waitUntil("LIVE_SSH_INITIAL_STOP_TIMEOUT") {
                    AppRuntime.state.value.hasSavedSettings && !AppRuntime.state.value.isSaving &&
                        AppRuntime.state.value.status == ProxyStatus.STOPPED &&
                        !serviceExists(context, ProxyService::class.java) && !serviceExists(context, HelperSetupService::class.java)
                }
                val store = SecureSettingsStore(context)
                val before = store.load()
                val prefs = context.getSharedPreferences("tgproxy.private.settings", Context.MODE_PRIVATE)
                val originalCiphertext = prefs.getString("encrypted_v1", null)
                checkSafe(before != null && originalCiphertext != null, "LIVE_SSH_PREVIOUS_PROFILE_REQUIRED")
                try {
                    @Suppress("DEPRECATION") val info = context.packageManager.getServiceInfo(
                        android.content.ComponentName(context, HelperSetupService::class.java), PackageManager.GET_META_DATA)
                    checkSafe(!info.exported, "LIVE_SSH_SERVICE_EXPORTED")
                    if (Build.VERSION.SDK_INT >= 29) checkSafe(info.foregroundServiceType and ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC != 0, "LIVE_SSH_SERVICE_WRONG_TYPE")
                    scenario.onActivity { AppRuntime.resetHelperSsh(); AppRuntime.probeHelperSsh(input.host, input.port.toString(), "root") }
                    waitUntil("LIVE_SSH_PREFLIGHT_TIMEOUT", 30, ::observeSetup) {
                        !AppRuntime.state.value.isSaving && AppRuntime.state.value.sshSetup.phase != SshSetupPhase.PROBING
                    }
                    val observed = AppRuntime.state.value.sshSetup
                    checkSafe(observed.phase == SshSetupPhase.CONFIRM_HOST_KEY, "LIVE_SSH_HOST_KEY_CONFIRMATION_MISSING")
                    checkSafe(observed.host == input.host && observed.port == input.port && observed.user == "root", "LIVE_SSH_ENDPOINT_CHANGED")
                    checkSafe(observed.fingerprint == input.hostKey, "LIVE_SSH_HOST_KEY_MISMATCH")
                    hostKeyMatched = true
                    scenario.onActivity { AppRuntime.confirmHelperSshKey() }
                    checkSafe(AppRuntime.state.value.sshSetup.phase == SshSetupPhase.READY, "LIVE_SSH_HOST_KEY_CONFIRM_FAILED")
                    scenario.onActivity { AppRuntime.deployHelperSsh(input.password, true, input.allowPrivateUpgrade) }
                    passwordCleared = input.password.all { it == '\u0000' }
                    checkSafe(passwordCleared, "LIVE_SSH_CALLER_PASSWORD_NOT_CLEARED")
                    waitUntil("LIVE_SSH_DEPLOY_TIMEOUT", 720, ::observeSetup) { !AppRuntime.state.value.isSaving }
                    checkSafe(AppRuntime.state.value.sshSetup.phase == SshSetupPhase.SUCCESS && AppRuntime.state.value.pairingStatus == PairingStatus.SUCCESS,
                        "LIVE_SSH_RUNTIME_NOT_SUCCESS")
                    checkSafe(foregroundSeen && notificationSeen && cancelActionSeen, "LIVE_SSH_PRIVATE_FGS_NOT_OBSERVED")
                    val saved = store.load()
                    checkSafe(saved != null && saved.helperEnabled && saved.helperRegistryManaged && saved.helperToken.isEmpty(), "LIVE_SSH_MANAGED_SETTINGS_INVALID")
                    checkSafe(saved!!.helperHost == input.host && saved.secretHex == before!!.secretHex && saved.port == before.port,
                        "LIVE_SSH_LOCAL_IDENTITY_CHANGED")
                    checkSafe(saved.ui() == AppRuntime.state.value.settings, "LIVE_SSH_UI_STORE_DIFFER")
                    input.expectedPin?.let { checkSafe(saved.helperFingerprint == it, "LIVE_SSH_HELPER_PIN_MISMATCH") }
                    leaseNotPersisted = true; runtimeSuccess = true
                    waitUntil("LIVE_SSH_FGS_FINISH_TIMEOUT") { !serviceExists(context, HelperSetupService::class.java) }
                    if (input.dataProbe) {
                        scenario.onActivity { ContextCompat.startForegroundService(it, Intent(it, ProxyService::class.java).setAction(ProxyService.ACTION_START)) }
                        waitUntil("LIVE_SSH_PROXY_START_TIMEOUT") { AppRuntime.state.value.status == ProxyStatus.RUNNING }
                        LivePairingRuntimeInstrumentedTest().anonymousReqPq(saved.port, saved.secretHex)
                        waitUntil("LIVE_SSH_HELPER_COUNTERS_MISSING") {
                            AppRuntime.state.value.metrics.let { it.helperConnections > 0 && it.bytesSent > 0 && it.bytesReceived > 0 }
                        }
                        realRoundTrip = true
                    }
                } catch (failure: Throwable) {
                    failureCode = if (failure is AssertionError && failure.message?.matches(Regex("LIVE_SSH_[A-Z0-9_]+")) == true) failure.message else "LIVE_SSH_RUNTIME_FAILED"
                } finally {
                    input.password.fill('\u0000')
                    try {
                        scenario.onActivity {
                            AppRuntime.cancelHelperSsh(); it.stopService(Intent(it, HelperSetupService::class.java))
                            it.stopService(Intent(it, ProxyService::class.java))
                        }
                        waitUntil("LIVE_SSH_CLEANUP_STOP_TIMEOUT", 60) {
                            !AppRuntime.state.value.isSaving && AppRuntime.state.value.status == ProxyStatus.STOPPED &&
                                !serviceExists(context, HelperSetupService::class.java) && !serviceExists(context, ProxyService::class.java)
                        }
                        ServerSocket().use { it.reuseAddress = true; it.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), before!!.port)) }
                        listenerClosed = true
                        scenario.onActivity { AppRuntime.resetHelperSsh(); AppRuntime.save(before!!.ui()) }
                        waitUntil("LIVE_SSH_RESTORE_TIMEOUT") { !AppRuntime.state.value.isSaving && AppRuntime.state.value.settings == before!!.ui() }
                        val loaded = store.load()
                        checkSafe(loaded != null && loaded.secretHex == before!!.secretHex && loaded.ui() == before.ui(), "LIVE_SSH_RESTORE_VALUES_CHANGED")
                        checkSafe(prefs.edit().putString("encrypted_v1", originalCiphertext).commit(), "LIVE_SSH_RESTORE_CIPHERTEXT_FAILED")
                        checkSafe(prefs.getString("encrypted_v1", null) == originalCiphertext, "LIVE_SSH_RESTORE_CIPHERTEXT_CHANGED")
                        restored = true
                    } catch (_: Throwable) { if (failureCode == null) failureCode = "LIVE_SSH_CLEANUP_FAILED" }
                }
            }
        } finally {
            input.password.fill('\u0000')
            val receipt = JSONObject().put("hostKeyMatchedBeforeAuthentication", hostKeyMatched)
                .put("explicitServerMutationConsent", true).put("explicitRegisteredDeviceConsent", true)
                .put("explicitExistingPrivateUpgradeConsent", input.allowPrivateUpgrade)
                .put("callerPasswordCleared", passwordCleared).put("privateSetupForegroundServiceSeen", foregroundSeen)
                .put("setupNotificationSeen", notificationSeen).put("setupNotificationCancelSeen", cancelActionSeen)
                .put("sshAndRegistryVerified", runtimeSuccess)
                .put("runtimeSuccess", runtimeSuccess && (!input.dataProbe || realRoundTrip) && restored && listenerClosed)
                .put("leaseNeverPersisted", leaseNotPersisted)
                .put("anonymousHelperResPqMatched", realRoundTrip).put("anonymousDataProbeRequested", input.dataProbe)
                .put("stoppedListenerClosed", listenerClosed).put("previousExactCiphertextAndSettingsRestored", restored)
                .put("lastSafePhase", safePhase).put("failureCode", failureCode ?: "NONE")
                .put("credentialsLogged", false).put("privateInputUnlinked", true)
            File(context.filesDir, "live-ssh-runtime-result.json").writeText(receipt.toString(2))
            instrumentation.sendStatus(0, Bundle().apply {
                putString("tgproxy_receipt_name", "live-ssh-runtime-result")
                putString("tgproxy_receipt_json", receipt.toString())
            })
        }
        failureCode?.let { throw AssertionError(it) }
    }
}
