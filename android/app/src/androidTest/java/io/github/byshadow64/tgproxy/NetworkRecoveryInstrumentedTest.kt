package io.github.byshadow64.tgproxy

import android.Manifest
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.byshadow64.tgproxy.ui.ProxySettingsUi
import io.github.byshadow64.tgproxy.ui.ProxyStatus
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import org.json.JSONObject

/** Opt-in changes only an owned emulator's Wi-Fi, restoring it in finally. No network probes. */
@RunWith(AndroidJUnit4::class)
class NetworkRecoveryInstrumentedTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private var settingsOpened = false
    private var originalAccessibilityFlags: Int? = null
    private fun waitFor(message: String, condition: () -> Boolean) {
        val until = System.nanoTime() + 20_000_000_000L
        while (!condition() && System.nanoTime() < until) Thread.sleep(50)
        assertTrue(message, condition())
    }
    private fun shell(command: String): String = ParcelFileDescriptor.AutoCloseInputStream(
        instrumentation.uiAutomation.executeShellCommand(command)).use { it.bufferedReader().readText() }

    private fun prepareWifiControl() {
        if (Build.VERSION.SDK_INT != 26) return
        // This API26 image denies shell UID2000 CHANGE_WIFI_STATE. Use its real
        // Settings switch rather than granting production permissions or faking callbacks.
        val automation = instrumentation.uiAutomation
        val info = automation.serviceInfo
        originalAccessibilityFlags = info.flags
        info.flags = info.flags or android.accessibilityservice.AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS
        automation.serviceInfo = info
        settingsOpened = true
        context.startActivity(Intent(android.provider.Settings.ACTION_WIFI_SETTINGS)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP))
        waitFor("Owned emulator Settings Wi-Fi switch") { wifiSwitchChecked() != null }
    }

    private fun <T> wifiSwitch(action: (android.view.accessibility.AccessibilityNodeInfo) -> T): T? {
        val root = instrumentation.uiAutomation.rootInActiveWindow ?: return null
        val switches = root.findAccessibilityNodeInfosByViewId("com.android.settings:id/switch_bar")
        return try {
            switches.singleOrNull { it.packageName?.toString() == "com.android.settings" && it.isCheckable }?.let(action)
        } finally {
            @Suppress("DEPRECATION")
            switches.forEach { it.recycle() }
            @Suppress("DEPRECATION")
            root.recycle()
        }
    }

    private fun wifiSwitchChecked(): Boolean? = wifiSwitch { it.isChecked }

    private fun setTestWifi(enabled: Boolean) {
        if (Build.VERSION.SDK_INT != 26) {
            shell(if (enabled) "svc wifi enable" else "svc wifi disable")
            return
        }
        waitFor("Owned emulator Wi-Fi switch ready") { wifiSwitch { it.isEnabled } == true }
        if (wifiSwitchChecked() != enabled) {
            assertTrue("Owned emulator Wi-Fi switch must accept its real click", wifiSwitch {
                it.performAction(android.view.accessibility.AccessibilityNodeInfo.ACTION_CLICK)
            } == true)
        }
        // Never repeat a successful click while Android is still changing state.
        waitFor("Owned emulator Wi-Fi switch state") { wifiSwitchChecked() == enabled }
    }

    private fun leaveWifiSettings() {
        try {
            if (settingsOpened) {
                instrumentation.uiAutomation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK)
                context.startActivity(Intent(context, MainActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP))
            }
        } finally {
            settingsOpened = false
            originalAccessibilityFlags?.let { previous ->
                val info = instrumentation.uiAutomation.serviceInfo
                info.flags = previous
                instrumentation.uiAutomation.serviceInfo = info
            }
            originalAccessibilityFlags = null
        }
    }

    @Test fun backgroundNetworkLossClosesStaleSessionsAndPreservesListenerAndLink() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("networkSwitchProbe") == "1")
        assumeTrue("Only owned Android emulators may change test connectivity", Build.HARDWARE in setOf("ranchu", "goldfish"))
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val originalNetwork = manager.activeNetwork
        assumeTrue(manager.getNetworkCapabilities(originalNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true)
        assumeTrue(shell("settings get global wifi_on").trim() == "1")
        if (Build.VERSION.SDK_INT >= 33) instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        val original = SecureSettingsStore(context).load()
        val prefs = context.getSharedPreferences("tgproxy.private.settings", Context.MODE_PRIVATE)
        val encrypted = prefs.getString("encrypted_v1", null)
        val local = InetAddress.getByName("127.0.0.1")
        val port = ServerSocket(0, 1, local).use { it.localPort }
        var wifiChanged = false
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            waitFor("Profile initialization") { AppRuntime.state.value.hasSavedSettings && !AppRuntime.state.value.isSaving }
            assertEquals(ProxyStatus.STOPPED, AppRuntime.state.value.status)
            scenario.onActivity { AppRuntime.save(ProxySettingsUi(localPort = port.toString())) }
            waitFor("Isolated profile save") { !AppRuntime.state.value.isSaving && AppRuntime.state.value.settings.localPort == port.toString() }
            try {
                scenario.onActivity { ContextCompat.startForegroundService(it,
                    Intent(it, ProxyService::class.java).setAction(ProxyService.ACTION_START)) }
                waitFor("Proxy listener start") { AppRuntime.state.value.status == ProxyStatus.RUNNING }
                val link = AppRuntime.telegramUri()
                assertNotNull("Running proxy must expose its applied connection link", link)
                scenario.moveToState(Lifecycle.State.CREATED)
                prepareWifiControl()
                assertEquals("Proxy activity must remain stopped during recovery", Lifecycle.State.CREATED, scenario.state)
                Socket(local, port).use { stale ->
                    val openedAt = android.os.SystemClock.elapsedRealtime()
                    stale.soTimeout = 6_000
                    waitFor("Pending handshake admission") { AppRuntime.state.value.metrics.activeConnections > 0 }
                    wifiChanged = true
                    setTestWifi(false)
                    waitFor("Owned emulator network loss") { manager.activeNetwork != originalNetwork }
                    assertEquals("Network change must not require reopening the proxy activity", Lifecycle.State.CREATED, scenario.state)
                    // A silent old-network socket otherwise waits for the handshake deadline.
                    val closed = try { stale.getInputStream().read() == -1 } catch (_: SocketException) { true }
                    assertTrue("Old session must close promptly on the service-owned network callback", closed)
                    assertTrue("Recovery must precede the unchanged 15-second handshake deadline",
                        android.os.SystemClock.elapsedRealtime() - openedAt < 12_000)
                }
                assertEquals(ProxyStatus.RUNNING, AppRuntime.state.value.status)
                assertTrue("Applied port/secret must not change during recovery", link == AppRuntime.telegramUri())
                // The original loopback listener still accepts connections while the UI is stopped.
                Socket(local, port).close()
                setTestWifi(true)
                waitFor("Owned emulator Wi-Fi restoration") {
                    manager.getNetworkCapabilities(manager.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
                }
                wifiChanged = false
                assertEquals(ProxyStatus.RUNNING, AppRuntime.state.value.status)
                assertTrue("Restored network must preserve the applied connection link", link == AppRuntime.telegramUri())
                instrumentation.sendStatus(0, Bundle().apply {
                    putString("tgproxy_receipt_name", "background-network-recovery")
                    putString("tgproxy_receipt_json", JSONObject().put("api", Build.VERSION.SDK_INT)
                        .put("staleSessionClosed", true).put("listenerPreserved", true)
                        .put("linkPreserved", true).put("activityStopped", true)
                        .put("emulatorWifiRestored", true).put("networkProbes", false).toString())
                })
            } finally {
                try {
                    if (wifiChanged) {
                        setTestWifi(true)
                        waitFor("Wi-Fi restored after test failure") {
                            manager.getNetworkCapabilities(manager.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
                        }
                    }
                } finally {
                    try { leaveWifiSettings() }
                    finally {
                        scenario.moveToState(Lifecycle.State.RESUMED)
                        scenario.onActivity { it.stopService(Intent(it, ProxyService::class.java)) }
                        waitFor("Proxy stop") { AppRuntime.state.value.status == ProxyStatus.STOPPED }
                        if (original != null && encrypted != null) {
                            scenario.onActivity { AppRuntime.save(original.ui()) }
                            waitFor("Original settings restored") { !AppRuntime.state.value.isSaving && AppRuntime.state.value.settings == original.ui() }
                            assertTrue(prefs.edit().putString("encrypted_v1", encrypted).commit())
                        }
                    }
                }
            }
        }
    }
}
