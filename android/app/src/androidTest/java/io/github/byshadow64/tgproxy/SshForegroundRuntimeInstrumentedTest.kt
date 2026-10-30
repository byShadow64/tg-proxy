package io.github.byshadow64.tgproxy

import android.app.ActivityManager
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.ParcelFileDescriptor
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.byshadow64.tgproxy.ui.ProxyStatus
import io.github.byshadow64.tgproxy.ui.SshSetupPhase
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.TimeUnit

/** Opt-in loopback SSH fixture only: actual JSch/FGS, auth gate, non-root rejection and Cancel. */
@RunWith(AndroidJUnit4::class)
class SshForegroundRuntimeInstrumentedTest {
    private fun waitUntil(code: String, condition: () -> Boolean) {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(18)
        while (System.nanoTime() < end) { if (condition()) return; Thread.sleep(20) }
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue("$code phase=${AppRuntime.state.value.sshSetup.phase} saving=${AppRuntime.state.value.isSaving} setupRunning=${running(context, HelperSetupService::class.java)}", condition())
    }
    @Suppress("DEPRECATION")
    private fun running(context: Context, type: Class<*>) = context.getSystemService(ActivityManager::class.java)
        .getRunningServices(Int.MAX_VALUE).any { it.service.className == type.name }
    @Test fun realSshPreflightRequiresKeyThenRootAndNotificationCancelsBackgroundWork() {
        val args = InstrumentationRegistry.getArguments()
        val port = args.getString("sshFixturePort")?.toIntOrNull()
        val fingerprint = args.getString("sshFixtureFingerprint")
        assumeTrue("Explicit owned local SSH fixture only", port != null && fingerprint != null)
        val inst = InstrumentationRegistry.getInstrumentation()
        val context = inst.targetContext
        val prefs = context.getSharedPreferences("tgproxy.private.settings", 0)
        val before = SecureSettingsStore(context).load()!!
        val originalCipher = prefs.getString("encrypted_v1", null)
        val notices = context.getSystemService(NotificationManager::class.java)
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { it.stopService(Intent(it, ProxyService::class.java)) }
            waitUntil("SSH_FIXTURE_PROXY_STOP") { AppRuntime.state.value.hasSavedSettings && !AppRuntime.state.value.isSaving &&
                AppRuntime.state.value.status == ProxyStatus.STOPPED && !running(context, ProxyService::class.java) }
            try {
                scenario.onActivity { AppRuntime.resetHelperSsh(); AppRuntime.probeHelperSsh("10.0.2.2", port.toString(), "root") }
                waitUntil("SSH_PREFLIGHT_NO_FGS") { notices.activeNotifications.any { it.id == HelperSetupService.NOTIFICATION_ID } }
                waitUntil("SSH_KEY_PREVIEW_MISSING") { !AppRuntime.state.value.isSaving && AppRuntime.state.value.sshSetup.phase == SshSetupPhase.CONFIRM_HOST_KEY }
                assertEquals("SSH_FIXTURE_KEY_MISMATCH", fingerprint, AppRuntime.state.value.sshSetup.fingerprint)
                val refused = "synthetic-fixture-password".toCharArray()
                scenario.onActivity { AppRuntime.deployHelperSsh(refused, true, false) }
                assertTrue("SSH_PASSWORD_NOT_CLEARED_AT_UNCONFIRMED_GATE", refused.all { it == '\u0000' })
                assertEquals(SshSetupPhase.CONFIRM_HOST_KEY, AppRuntime.state.value.sshSetup.phase)
                scenario.onActivity { AppRuntime.confirmHelperSshKey() }
                assertEquals(SshSetupPhase.READY, AppRuntime.state.value.sshSetup.phase)
                val password = "synthetic-fixture-password".toCharArray()
                scenario.onActivity { AppRuntime.deployHelperSsh(password, true, false) }
                assertTrue("SSH_CALLER_PASSWORD_NOT_CLEARED", password.all { it == '\u0000' })
                waitUntil("SSH_NONROOT_NOT_REJECTED") { !AppRuntime.state.value.isSaving && AppRuntime.state.value.sshSetup.phase == SshSetupPhase.ERROR }
                assertEquals(context.getString(R.string.ssh_root_required), AppRuntime.state.value.sshSetup.progressMessage)
                // The previous task publishes its terminal UI state before Service.onDestroy completes.
                // Do not mistake the previous run's PendingIntent for the newly started run's Cancel.
                waitUntil("SSH_NONROOT_FGS_NOT_STOPPED") { !running(context, HelperSetupService::class.java) &&
                    notices.activeNotifications.none { it.id == HelperSetupService.NOTIFICATION_ID } }
                scenario.onActivity { AppRuntime.resetHelperSsh(); AppRuntime.probeHelperSsh("10.0.2.2", port.toString(), "root") }
                waitUntil("SSH_CANCEL_NO_FGS") { notices.activeNotifications.any { it.id == HelperSetupService.NOTIFICATION_ID } }
                ParcelFileDescriptor.AutoCloseInputStream(inst.uiAutomation.executeShellCommand("input keyevent 3")).use { it.readBytes() }
                waitUntil("SSH_HOME_DID_NOT_BACKGROUND_ACTIVITY") { scenario.state == Lifecycle.State.CREATED }
                val notification = notices.activeNotifications.single { it.id == HelperSetupService.NOTIFICATION_ID }.notification
                val cancel = notification.actions.single { it.title.toString() == context.getString(R.string.ui_cancel) }
                assertTrue(notification.flags and android.app.Notification.FLAG_ONGOING_EVENT != 0)
                cancel.actionIntent.send()
                waitUntil("SSH_CANCEL_NOT_FINISHED") { !AppRuntime.state.value.isSaving && AppRuntime.state.value.sshSetup.phase == SshSetupPhase.CANCELLED &&
                    !running(context, HelperSetupService::class.java) }
                assertFalse(notices.activeNotifications.any { it.id == HelperSetupService.NOTIFICATION_ID })
                assertEquals("SSH_FIXTURE_SETTINGS_CHANGED", before.ui(), SecureSettingsStore(context).load()!!.ui())
                assertEquals("SSH_FIXTURE_CIPHER_CHANGED", originalCipher, prefs.getString("encrypted_v1", null))
                inst.sendStatus(0, Bundle().apply {
                    putString("tgproxy_receipt_name", "ssh-foreground-fixture-result")
                    putString("tgproxy_receipt_json", JSONObject().put("actualJschAndForegroundService", true)
                        .put("exactKeyBeforePassword", true).put("nonRootRejected", true).put("callerPasswordCleared", true)
                        .put("backgroundNotificationCancel", true).put("settingsAndCipherUnchanged", true)
                        .put("serverMutationAttempted", false).put("ownedLoopbackFixture", true).toString())
                })
            } finally {
                scenario.onActivity { AppRuntime.cancelHelperSsh(); it.stopService(Intent(it, HelperSetupService::class.java)) }
            }
        }
    }
}
