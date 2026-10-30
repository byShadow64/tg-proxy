package io.github.byshadow64.tgproxy

import android.Manifest
import android.app.Activity
import android.app.Instrumentation
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.os.Build
import androidx.core.content.ContextCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.byshadow64.tgproxy.ui.ProxyStatus
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/** Exercises real Activity actions without dispatching credentials to another app or a browser. */
@RunWith(AndroidJUnit4::class)
class ConnectionLinkActionsInstrumentedTest {
    private fun waitUntil(label: String, condition: () -> Boolean) {
        val end = System.nanoTime() + 15_000_000_000L
        while (System.nanoTime() < end) {
            if (condition()) return
            Thread.sleep(50)
        }
        assertTrue(label, condition())
    }

    @Suppress("DEPRECATION")
    @Test fun actualCopyAndOpenUseRunningProfileAndStopRejectsStaleActions() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        lateinit var clipboard: ClipboardManager
        instrumentation.runOnMainSync { clipboard = context.getSystemService(ClipboardManager::class.java) }
        val privatePrefs = context.getSharedPreferences("tgproxy.private.settings", 0)
        val chooserCalls = AtomicInteger()
        val capturedChooser = AtomicReference<Intent?>()
        val monitor = object : Instrumentation.ActivityMonitor() {
            override fun onStartActivity(intent: Intent): Instrumentation.ActivityResult? {
                if (intent.action != Intent.ACTION_CHOOSER) return null
                chooserCalls.incrementAndGet()
                capturedChooser.set(Intent(intent))
                return Instrumentation.ActivityResult(Activity.RESULT_CANCELED, null)
            }
        }
        var originalClipboard: ClipData? = null
        var originalCiphertext: String? = null
        var originalSettings: AppSettings? = null
        var monitorAdded = false
        if (Build.VERSION.SDK_INT >= 33) {
            instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        }
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            waitUntil("LINK_SETTINGS_NOT_READY") {
                AppRuntime.state.value.hasSavedSettings && !AppRuntime.state.value.isSaving
            }
            assertTrue("LINK_TEST_REQUIRES_STOPPED_PROXY", AppRuntime.state.value.status == ProxyStatus.STOPPED)
            originalSettings = SecureSettingsStore(context).load()
            originalCiphertext = privatePrefs.getString("encrypted_v1", null)
            assertNotNull("LINK_SETTINGS_MISSING", originalSettings)
            scenario.onActivity {
                originalClipboard = clipboard.primaryClip?.let { clip -> ClipData(clip) }
                clipboard.setPrimaryClip(ClipData.newPlainText("TG Proxy test", "connection-link-test-sentinel"))
            }
            instrumentation.addMonitor(monitor)
            monitorAdded = true
            try {
                scenario.onActivity { activity ->
                    assertNull("LINK_STOPPED_URI", AppRuntime.telegramUri())
                    assertNull("LINK_STOPPED_WEB_URI", AppRuntime.telegramUri(web = true))
                    activity.copyTelegramLink()
                    activity.openTelegram()
                    assertTrue("LINK_STOPPED_CLIPBOARD_CHANGED",
                        clipboard.primaryClip?.getItemAt(0)?.text?.toString() == "connection-link-test-sentinel")
                }
                assertTrue("LINK_STOPPED_DISPATCH", chooserCalls.get() == 0)

                val loopback = InetAddress.getByName("127.0.0.1")
                val appliedPort = ServerSocket(0, 1, loopback).use { it.localPort }
                scenario.onActivity {
                    AppRuntime.save(originalSettings!!.ui().copy(localPort = appliedPort.toString(), helperEnabled = false))
                }
                waitUntil("LINK_TEST_PROFILE_NOT_SAVED") {
                    !AppRuntime.state.value.isSaving && AppRuntime.state.value.settings.localPort == appliedPort.toString()
                }
                scenario.onActivity { activity ->
                    ContextCompat.startForegroundService(activity,
                        Intent(activity, ProxyService::class.java).setAction(ProxyService.ACTION_START))
                }
                waitUntil("LINK_PROXY_NOT_RUNNING") { AppRuntime.state.value.status == ProxyStatus.RUNNING }
                val appliedSecret = "dd" + originalSettings!!.secretHex
                val initialTg = AppRuntime.telegramUri()
                val initialWeb = AppRuntime.telegramUri(web = true)
                assertNotNull("LINK_RUNNING_URI_MISSING", initialTg)
                assertNotNull("LINK_RUNNING_WEB_URI_MISSING", initialWeb)
                assertTrue("LINK_NATIVE_SCHEME", initialTg!!.scheme == "tg" && initialTg.authority == "proxy")
                assertTrue("LINK_WEB_SCHEME", initialWeb!!.scheme == "https" && initialWeb.authority == "t.me" && initialWeb.path == "/proxy")
                for (uri in listOf(initialTg, initialWeb)) {
                    assertTrue("LINK_APPLIED_HOST", uri.getQueryParameter("server") == "127.0.0.1")
                    assertTrue("LINK_APPLIED_PORT", uri.getQueryParameter("port") == appliedPort.toString())
                    assertTrue("LINK_APPLIED_SECRET", uri.getQueryParameter("secret") == appliedSecret)
                    assertTrue("LINK_EXTRA_QUERY", uri.queryParameterNames == setOf("server", "port", "secret"))
                }

                // A saved future configuration must never be advertised as the active listener.
                var draftPort: Int
                do { draftPort = ServerSocket(0, 1, loopback).use { it.localPort } } while (draftPort == appliedPort)
                scenario.onActivity { AppRuntime.save(AppRuntime.state.value.settings.copy(localPort = draftPort.toString())) }
                waitUntil("LINK_DRAFT_PROFILE_NOT_SAVED") {
                    !AppRuntime.state.value.isSaving && AppRuntime.state.value.settings.localPort == draftPort.toString()
                }
                scenario.onActivity { activity ->
                    activity.copyTelegramLink()
                    val clip = clipboard.primaryClip
                    assertTrue("LINK_COPY_ITEM_COUNT", clip?.itemCount == 1)
                    val copied = clip!!.getItemAt(0).text?.toString()
                    assertTrue("LINK_CLIPBOARD_NOT_APPLIED_WEB_URI", copied == initialWeb.toString())
                    assertTrue("LINK_CLIPBOARD_NOT_SENSITIVE",
                        clip.description.extras?.getBoolean("android.content.extra.IS_SENSITIVE", false) == true)
                    assertTrue("LINK_NATIVE_CHANGED_AFTER_DRAFT", AppRuntime.telegramUri() == initialTg)
                    activity.openTelegram()
                }
                assertTrue("LINK_CHOOSER_NOT_OPENED_ONCE", chooserCalls.get() == 1)
                val chooser = capturedChooser.get()
                assertTrue("LINK_CHOOSER_ACTION", chooser?.action == Intent.ACTION_CHOOSER)
                val target = chooser!!.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                assertNotNull("LINK_CHOOSER_TARGET_MISSING", target)
                assertTrue("LINK_CHOOSER_TARGET_ACTION", target!!.action == Intent.ACTION_VIEW)
                assertTrue("LINK_CHOOSER_NOT_BROWSABLE", target.hasCategory(Intent.CATEGORY_BROWSABLE))
                assertTrue("LINK_CHOOSER_NOT_APPLIED_URI", target.data == initialTg)
                assertTrue("LINK_CHOOSER_FORCED_CLIENT", target.`package` == null && target.component == null)
                assertTrue("LINK_COPY_NOT_IN_JOURNAL", !AppRuntime.journalReport().contains(originalSettings!!.secretHex))

                scenario.onActivity { it.startService(Intent(it, ProxyService::class.java).setAction(ProxyService.ACTION_STOP)) }
                waitUntil("LINK_PROXY_DID_NOT_STOP") { AppRuntime.state.value.status == ProxyStatus.STOPPED }
                scenario.onActivity { activity ->
                    clipboard.setPrimaryClip(ClipData.newPlainText("TG Proxy test", "connection-link-stopped-sentinel"))
                    activity.copyTelegramLink()
                    activity.openTelegram()
                    assertTrue("LINK_STALE_COPY_AFTER_STOP",
                        clipboard.primaryClip?.getItemAt(0)?.text?.toString() == "connection-link-stopped-sentinel")
                    assertNull("LINK_STOPPED_WEB_REMAINS", AppRuntime.telegramUri(web = true))
                }
                assertTrue("LINK_STALE_DISPATCH_AFTER_STOP", chooserCalls.get() == 1)
                assertTrue("LINK_SECRET_IN_JOURNAL", !AppRuntime.journalReport().contains(originalSettings!!.secretHex))
            } finally {
                if (monitorAdded) instrumentation.removeMonitor(monitor)
                scenario.onActivity { it.stopService(Intent(it, ProxyService::class.java)) }
                waitUntil("LINK_CLEANUP_PROXY_NOT_STOPPED") { AppRuntime.state.value.status == ProxyStatus.STOPPED }
                originalSettings?.let { previous ->
                    scenario.onActivity { AppRuntime.save(previous.ui()) }
                    waitUntil("LINK_CLEANUP_SETTINGS_NOT_RESTORED") {
                        !AppRuntime.state.value.isSaving && AppRuntime.state.value.settings == previous.ui()
                    }
                    originalCiphertext?.let { cipher ->
                        assertTrue("LINK_CLEANUP_CIPHERTEXT_NOT_RESTORED",
                            privatePrefs.edit().putString("encrypted_v1", cipher).commit())
                    }
                }
                scenario.onActivity {
                    if (originalClipboard != null) clipboard.setPrimaryClip(originalClipboard!!)
                    else if (Build.VERSION.SDK_INT >= 28) clipboard.clearPrimaryClip()
                    else clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
                }
            }
        }
    }
}
