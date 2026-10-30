package io.github.byshadow64.tgproxy

import android.Manifest
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
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** Exercises the real save/start guard and local listener; never connects to an upstream. */
@RunWith(AndroidJUnit4::class)
class SettingsApplyRestartInstrumentedTest {
    private fun waitUntil(condition: () -> Boolean) {
        val deadline = System.nanoTime() + 12_000_000_000L
        while (System.nanoTime() < deadline) { if (condition()) return; Thread.sleep(25) }
        assertTrue("Expected saved profile/listener state was not reached", condition())
    }

    @Test fun applyAndRestartUsesSavedPortAfterReleasingSaveGuard() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        if (Build.VERSION.SDK_INT >= 33)
            instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            waitUntil { AppRuntime.state.value.hasSavedSettings && !AppRuntime.state.value.isSaving && AppRuntime.state.value.status == ProxyStatus.STOPPED }
            val originalSettings = SecureSettingsStore(context).load()!!
            val preferences = context.getSharedPreferences("tgproxy.private.settings", 0)
            val originalCiphertext = preferences.getString("encrypted_v1", null)!!
            val loopback = InetAddress.getByName("127.0.0.1")
            val ports = ServerSocket(0, 1, loopback).use { first ->
                ServerSocket(0, 1, loopback).use { second -> first.localPort to second.localPort }
            }
            val (firstPort, secondPort) = ports
            val callbacks = AtomicInteger()
            val allowed = AtomicBoolean(false)
            fun currentPort() = AppRuntime.telegramUri()?.getQueryParameter("port")
            try {
                scenario.onActivity { AppRuntime.save(ProxySettingsUi(localPort = firstPort.toString())) }
                waitUntil { !AppRuntime.state.value.isSaving && AppRuntime.state.value.settings.localPort == firstPort.toString() }
                scenario.onActivity { ContextCompat.startForegroundService(it,
                    Intent(it, ProxyService::class.java).setAction(ProxyService.ACTION_START)) }
                waitUntil { AppRuntime.state.value.status == ProxyStatus.RUNNING }
                assertEquals(firstPort, AppRuntime.state.value.runningPort)

                // Save alone changes the next profile; overview/link retain the actual listener.
                scenario.onActivity { AppRuntime.save(ProxySettingsUi(localPort = secondPort.toString())) }
                waitUntil { !AppRuntime.state.value.isSaving && AppRuntime.state.value.settings.localPort == secondPort.toString() }
                assertEquals(firstPort, AppRuntime.state.value.runningPort)
                assertEquals(firstPort.toString(), currentPort())

                Socket(loopback, firstPort).use { pending ->
                    pending.soTimeout = 4_000
                    scenario.onActivity { activity ->
                        AppRuntime.save(ProxySettingsUi(localPort = secondPort.toString())) {
                            callbacks.incrementAndGet()
                            allowed.set(AppRuntime.canStart())
                            if (AppRuntime.canStart()) ContextCompat.startForegroundService(activity,
                                Intent(activity, ProxyService::class.java).setAction(ProxyService.ACTION_RESTART))
                        }
                    }
                    waitUntil { callbacks.get() == 1 && AppRuntime.state.value.status == ProxyStatus.RUNNING && currentPort() == secondPort.toString() }
                    assertTrue("Restart must be enabled after completed persistence", allowed.get())
                    assertEquals(secondPort, AppRuntime.state.value.runningPort)
                    assertEquals(-1, pending.getInputStream().read())
                }
                ServerSocket().use { it.reuseAddress = true; it.bind(InetSocketAddress(loopback, firstPort)) }
                Socket(loopback, secondPort).close()

                // Invalid input must neither invoke the callback nor disturb the active profile.
                scenario.onActivity { AppRuntime.save(ProxySettingsUi(localPort = "0")) { callbacks.incrementAndGet() } }
                waitUntil { !AppRuntime.state.value.isSaving && AppRuntime.state.value.validationErrors.isNotEmpty() }
                assertEquals(1, callbacks.get())
                assertEquals(secondPort.toString(), currentPort())
                assertEquals(secondPort, SecureSettingsStore(context).load()!!.port)
            } finally {
                scenario.onActivity { it.stopService(Intent(it, ProxyService::class.java)) }
                waitUntil { AppRuntime.state.value.status == ProxyStatus.STOPPED }
                assertNull(AppRuntime.state.value.runningPort)
                scenario.onActivity { AppRuntime.save(originalSettings.ui()) }
                waitUntil { !AppRuntime.state.value.isSaving && AppRuntime.state.value.settings == originalSettings.ui() }
                assertTrue(preferences.edit().putString("encrypted_v1", originalCiphertext).commit())
            }
        }
    }
}
