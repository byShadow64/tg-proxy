package io.github.byshadow64.tgproxy

import android.Manifest
import android.app.NotificationManager
import android.content.Intent
import android.os.Build
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.byshadow64.tgproxy.ui.ProxySettingsUi
import io.github.byshadow64.tgproxy.ui.ProxyStatus
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

@RunWith(AndroidJUnit4::class)
class ProxyServiceInstrumentedTest {
    private fun networkWakeHeld(): Boolean = android.os.ParcelFileDescriptor.AutoCloseInputStream(
        InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand("dumpsys power")).use {
        it.bufferedReader().readText().lineSequence().any { line -> line.contains("PARTIAL_WAKE_LOCK") && line.contains("TGProxy:ActiveNetwork") }
    }
    private fun waitUntil(condition: () -> Boolean) {
        val end = System.nanoTime() + 12_000_000_000L
        while (System.nanoTime() < end) { if (condition()) return; Thread.sleep(50) }
        assertTrue("Expected lifecycle condition was not reached", condition())
    }
    @Test fun foregroundStopActionClosesPendingHandshakeAndRestartWorks() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val originalSettings = SecureSettingsStore(context).load()
        val privatePrefs = context.getSharedPreferences("tgproxy.private.settings", 0)
        val originalCiphertext = privatePrefs.getString("encrypted_v1", null)
        if (Build.VERSION.SDK_INT >= 33) instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        val loopback = InetAddress.getByName("127.0.0.1")
        val port = ServerSocket(0, 1, loopback).use { it.localPort }
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            waitUntil { AppRuntime.state.value.hasSavedSettings && !AppRuntime.state.value.isSaving && AppRuntime.state.value.status == ProxyStatus.STOPPED }
            scenario.onActivity { AppRuntime.save(ProxySettingsUi(localPort = port.toString())) }
            waitUntil { !AppRuntime.state.value.isSaving && AppRuntime.state.value.settings.localPort == port.toString() }
            fun start() = scenario.onActivity { ContextCompat.startForegroundService(it, Intent(it, ProxyService::class.java).setAction(ProxyService.ACTION_START)) }
            fun stop() = scenario.onActivity { it.startService(Intent(it, ProxyService::class.java).setAction(ProxyService.ACTION_STOP)) }
            try {
                start(); waitUntil { AppRuntime.state.value.status == ProxyStatus.RUNNING }
                scenario.onActivity { ContextCompat.startForegroundService(it,
                    Intent(it, ProxyService::class.java).setAction("obsolete-internal-command")) }
                Thread.sleep(300)
                assertEquals("Obsolete command must preserve the active listener", ProxyStatus.RUNNING, AppRuntime.state.value.status)
                assertFalse("Quiet listener must not hold CPU awake", networkWakeHeld())
                val uri = AppRuntime.telegramUri()
                assertEquals("127.0.0.1", uri!!.getQueryParameter("server"))
                assertEquals(port.toString(), uri.getQueryParameter("port"))
                assertTrue(uri.getQueryParameter("secret")!!.matches(Regex("dd[0-9a-f]{32}")))
                val pending = Socket(loopback, port).apply { soTimeout = 4000 }
                try {
                    waitUntil { AppRuntime.state.value.metrics.activeConnections > 0 }
                    waitUntil { networkWakeHeld() }
                    val notifications = context.getSystemService(NotificationManager::class.java).activeNotifications
                    val notification = notifications.single { it.packageName == context.packageName }.notification
                    assertTrue(notification.flags and android.app.Notification.FLAG_ONGOING_EVENT != 0)
                    val stopAction = notification.actions.single { it.title.toString() == context.getString(R.string.service_stop) }
                    assertNotNull(stopAction.actionIntent)
                    assertNotNull("Collapsed notification must expose a stop control", notification.contentView)
                    assertNotNull(notification.bigContentView)
                    instrumentation.runOnMainSync {
                        val compact = notification.contentView.apply(context, null)
                        val button = compact.findViewById<android.widget.TextView>(R.id.notification_stop)
                        assertEquals(context.getString(R.string.service_stop), button.text.toString())
                        assertEquals(android.view.View.VISIBLE, button.visibility)
                        assertNotNull("Compact Stop needs its own contrasting surface", button.background)
                        val density = context.resources.displayMetrics.density
                        val stopBackground = android.graphics.Bitmap.createBitmap((96 * density).toInt(), (48 * density).toInt(), android.graphics.Bitmap.Config.ARGB_8888)
                        button.background.setBounds(0, 0, stopBackground.width, stopBackground.height)
                        button.background.draw(android.graphics.Canvas(stopBackground))
                        assertTrue("Compact Stop text must remain legible on either native shade", androidx.core.graphics.ColorUtils.calculateContrast(
                            button.currentTextColor, stopBackground.getPixel(stopBackground.width / 2, stopBackground.height / 2)) >= 4.5)
                        stopBackground.recycle()
                        val expanded = notification.bigContentView.apply(context, null)
                        assertEquals(android.view.View.GONE, expanded.findViewById<android.widget.TextView>(R.id.notification_stop).visibility)
                        assertEquals(context.getString(R.string.service_notification), expanded.findViewById<android.widget.TextView>(R.id.notification_title).text.toString())
                        // Invoke the actual PendingIntent wired into the compact RemoteViews.
                        assertTrue(button.performClick())
                    }
                    waitUntil { AppRuntime.state.value.status == ProxyStatus.STOPPED }
                    waitUntil { !networkWakeHeld() }
                    assertEquals(-1, pending.getInputStream().read())
                } finally { pending.close() }
                assertNull(AppRuntime.telegramUri())
                ServerSocket().use { it.reuseAddress = true; it.bind(InetSocketAddress(loopback, port)) }
                // Repeated user commands must leave only the last requested listener running.
                repeat(3) { start(); stop() }
                start(); waitUntil { AppRuntime.state.value.status == ProxyStatus.RUNNING }
                Socket(loopback, port).close()
                // Leaving the activity must not stop an explicitly started foreground proxy.
                scenario.moveToState(Lifecycle.State.CREATED)
                Thread.sleep(200)
                assertEquals(ProxyStatus.RUNNING, AppRuntime.state.value.status)
                scenario.moveToState(Lifecycle.State.RESUMED)
                stop(); waitUntil { AppRuntime.state.value.status == ProxyStatus.STOPPED }
                ServerSocket().use { it.reuseAddress = true; it.bind(InetSocketAddress(loopback, port)) }
            } finally {
                scenario.onActivity { it.stopService(Intent(it, ProxyService::class.java)) }
                waitUntil { AppRuntime.state.value.status == ProxyStatus.STOPPED }
                if (originalSettings != null && originalCiphertext != null) {
                    scenario.onActivity { AppRuntime.save(originalSettings.ui()) }
                    waitUntil { !AppRuntime.state.value.isSaving && AppRuntime.state.value.settings == originalSettings.ui() }
                    assertTrue(privatePrefs.edit().putString("encrypted_v1", originalCiphertext).commit())
                }
            }
        }
    }

    @Test fun staleForegroundStartsCleanUpWithoutAndroidDeadlineCrash() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        if (Build.VERSION.SDK_INT >= 33) instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            waitUntil { AppRuntime.state.value.hasSavedSettings && !AppRuntime.state.value.isSaving }
            assertEquals(ProxyStatus.STOPPED, AppRuntime.state.value.status)
            for (action in listOf<String?>(null, "obsolete-internal-command")) {
                scenario.onActivity { ContextCompat.startForegroundService(it, Intent(it, ProxyService::class.java).setAction(action)) }
                Thread.sleep(300)
                waitUntil {
                    @Suppress("DEPRECATION")
                    val running = context.getSystemService(android.app.ActivityManager::class.java).getRunningServices(Int.MAX_VALUE)
                    running.none { it.service.className == ProxyService::class.java.name } &&
                        context.getSystemService(NotificationManager::class.java).activeNotifications.none { it.id == 1 }
                }
            }
            // The framework reports a missed foreground promotion asynchronously.
            Thread.sleep(6_000)
            assertEquals(ProxyStatus.STOPPED, AppRuntime.state.value.status)
        }
    }
}
