package io.github.byshadow64.tgproxy

import android.Manifest
import android.app.ActivityManager
import android.app.NotificationManager
import android.content.Intent
import android.os.Build
import androidx.core.content.ContextCompat
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
import java.net.SocketException

/** Real foreground-service commands and local sockets only; no upstream requests. */
@RunWith(AndroidJUnit4::class)
class ReconnectInstrumentedTest {
    private fun waitUntil(condition: () -> Boolean) {
        val deadline = System.nanoTime() + 12_000_000_000L
        while (System.nanoTime() < deadline) { if (condition()) return; Thread.sleep(25) }
        assertTrue("Expected reconnect/listener state was not reached", condition())
    }

    @Test fun reconnectKeepsAppliedProfileAndStopWinsQueuedCommands() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        if (Build.VERSION.SDK_INT >= 33)
            instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            waitUntil {
                AppRuntime.state.value.hasSavedSettings && !AppRuntime.state.value.isSaving &&
                    AppRuntime.state.value.status == ProxyStatus.STOPPED
            }
            val originalSettings = SecureSettingsStore(context).load()!!
            val preferences = context.getSharedPreferences("tgproxy.private.settings", 0)
            val originalCiphertext = preferences.getString("encrypted_v1", null)!!
            val loopback = InetAddress.getByName("127.0.0.1")
            val (firstPort, secondPort) = ServerSocket(0, 1, loopback).use { first ->
                ServerSocket(0, 1, loopback).use { second -> first.localPort to second.localPort }
            }
            fun reconnect() = scenario.onActivity {
                ContextCompat.startForegroundService(it,
                    Intent(it, ProxyService::class.java).setAction(ProxyService.ACTION_RECONNECT))
            }
            fun listenerReleased(port: Int) {
                ServerSocket().use { it.reuseAddress = true; it.bind(InetSocketAddress(loopback, port)) }
            }
            fun assertPeerClosed(socket: Socket, message: String) {
                try { assertEquals(message, -1, socket.getInputStream().read()) }
                catch (_: SocketException) {
                    // Closing an unfinished handshake may deliver either FIN or RST.
                    // SocketTimeoutException is deliberately not accepted here.
                }
            }
            fun noServiceOrNotification(): Boolean {
                @Suppress("DEPRECATION")
                val services = context.getSystemService(ActivityManager::class.java).getRunningServices(Int.MAX_VALUE)
                return services.none { it.service.className == ProxyService::class.java.name } &&
                    context.getSystemService(NotificationManager::class.java).activeNotifications.none { it.id == 1 }
            }
            try {
                scenario.onActivity { AppRuntime.save(ProxySettingsUi(localPort = firstPort.toString())) }
                waitUntil { !AppRuntime.state.value.isSaving && AppRuntime.state.value.settings.localPort == firstPort.toString() }
                scenario.onActivity {
                    ContextCompat.startForegroundService(it,
                        Intent(it, ProxyService::class.java).setAction(ProxyService.ACTION_START))
                }
                waitUntil { AppRuntime.state.value.status == ProxyStatus.RUNNING }
                val appliedUri = AppRuntime.telegramUri()!!
                assertEquals(firstPort, AppRuntime.state.value.runningPort)

                // A saved next-launch profile must not be silently applied by Reconnect.
                scenario.onActivity { AppRuntime.save(ProxySettingsUi(localPort = secondPort.toString())) }
                waitUntil { !AppRuntime.state.value.isSaving && AppRuntime.state.value.settings.localPort == secondPort.toString() }
                Socket(loopback, firstPort).use { pending ->
                    pending.soTimeout = 4_000
                    waitUntil { AppRuntime.state.value.metrics.activeConnections > 0 }
                    reconnect()
                    // Waiting for the old socket to close avoids accepting the pre-command RUNNING state.
                    assertPeerClosed(pending, "Reconnect must close the previous pending handshake")
                    waitUntil { AppRuntime.state.value.status == ProxyStatus.RUNNING }
                }
                assertEquals(firstPort, AppRuntime.state.value.runningPort)
                // Uri equality includes the secret; never print the Uri in an assertion or receipt.
                assertTrue("Reconnect must preserve the exact applied connection link", appliedUri == AppRuntime.telegramUri())
                assertEquals(secondPort, SecureSettingsStore(context).load()!!.port)
                assertEquals(secondPort.toString(), AppRuntime.state.value.settings.localPort)
                Socket(loopback, firstPort).use { pending ->
                    pending.soTimeout = 4_000
                    waitUntil { AppRuntime.state.value.metrics.activeConnections > 0 }
                    // Android receives these service commands in order. The final Stop must
                    // invalidate queued reconnect work; a following stale reconnect cannot undo it.
                    scenario.onActivity { activity ->
                        repeat(2) {
                            ContextCompat.startForegroundService(activity,
                                Intent(activity, ProxyService::class.java).setAction(ProxyService.ACTION_RECONNECT))
                        }
                        activity.startService(Intent(activity, ProxyService::class.java).setAction(ProxyService.ACTION_STOP))
                        ContextCompat.startForegroundService(activity,
                            Intent(activity, ProxyService::class.java).setAction(ProxyService.ACTION_RECONNECT))
                    }
                    assertPeerClosed(pending, "Stop must close the pending local connection")
                    waitUntil { AppRuntime.state.value.status == ProxyStatus.STOPPED && noServiceOrNotification() }
                }
                assertNull(AppRuntime.telegramUri())
                assertNull(AppRuntime.state.value.runningPort)
                listenerReleased(firstPort)
                listenerReleased(secondPort)

                // Reconnect sent to an already stopped service must remain a no-op,
                // including cleanup of the foreground promotion required by Android.
                reconnect()
                instrumentation.waitForIdleSync()
                Thread.sleep(300)
                waitUntil { AppRuntime.state.value.status == ProxyStatus.STOPPED && noServiceOrNotification() }
                assertNull(AppRuntime.telegramUri())
                assertEquals(secondPort, SecureSettingsStore(context).load()!!.port)
                listenerReleased(firstPort)
                listenerReleased(secondPort)
            } finally {
                scenario.onActivity { it.stopService(Intent(it, ProxyService::class.java)) }
                waitUntil { AppRuntime.state.value.status == ProxyStatus.STOPPED }
                scenario.onActivity { AppRuntime.save(originalSettings.ui()) }
                waitUntil { !AppRuntime.state.value.isSaving && AppRuntime.state.value.settings == originalSettings.ui() }
                assertTrue("Original emulator ciphertext must be restored",
                    preferences.edit().putString("encrypted_v1", originalCiphertext).commit())
                val restored = SecureSettingsStore(context).load()!!
                assertTrue("Original emulator profile must be restored",
                    originalSettings.ui() == restored.ui() && originalSettings.secretHex == restored.secretHex)
            }
        }
    }
}
