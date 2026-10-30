package io.github.byshadow64.tgproxy

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.net.TrafficStats
import android.os.Bundle
import android.os.Process
import androidx.core.content.ContextCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.byshadow64.tgproxy.ui.ProxyStatus
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.TimeUnit

/** No Telegram peer: a real running background listener must not poll routes or move payload. */
@RunWith(AndroidJUnit4::class)
class IdleTrafficInstrumentedTest {
    private fun waitUntil(label: String, condition: () -> Boolean) {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
        while (System.nanoTime() < end) {
            if (condition()) return
            Thread.sleep(40)
        }
        assertTrue(label, condition())
    }

    @Suppress("DEPRECATION")
    private fun serviceExists(context: Context) = context.getSystemService(ActivityManager::class.java)
        .getRunningServices(Int.MAX_VALUE).any { it.service.className == ProxyService::class.java.name }

    @Test fun backgroundListenerHasNoUnsolicitedTrafficAndStopsCleanly() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val store = SecureSettingsStore(context)
        val prefs = context.getSharedPreferences("tgproxy.private.settings", 0)
        val previous = store.load()
        assertTrue("IDLE_PREVIOUS_PROFILE_REQUIRED", previous != null)
        val cipher = prefs.getString("encrypted_v1", null)
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { it.stopService(Intent(it, ProxyService::class.java)) }
            waitUntil("IDLE_STOP_BARRIER") { !serviceExists(context) && !AppRuntime.state.value.isSaving && AppRuntime.state.value.hasSavedSettings }
            try {
                scenario.onActivity { AppRuntime.save(previous!!.ui().copy(helperEnabled = false)) }
                waitUntil("IDLE_SAVE_TIMEOUT") { !AppRuntime.state.value.isSaving && !AppRuntime.state.value.settings.helperEnabled }
                scenario.onActivity { ContextCompat.startForegroundService(it, Intent(it, ProxyService::class.java).setAction(ProxyService.ACTION_START)) }
                waitUntil("IDLE_START_TIMEOUT") { AppRuntime.state.value.status == ProxyStatus.RUNNING }
                Thread.sleep(1_100)
                val before = AppRuntime.state.value.metrics
                val uid = Process.myUid()
                val rx = TrafficStats.getUidRxBytes(uid)
                val tx = TrafficStats.getUidTxBytes(uid)
                android.os.ParcelFileDescriptor.AutoCloseInputStream(
                    instrumentation.uiAutomation.executeShellCommand("input keyevent 3")
                ).use { it.readBytes() }
                Thread.sleep(20_000)
                val after = AppRuntime.state.value.metrics
                val rxAfter = TrafficStats.getUidRxBytes(uid)
                val txAfter = TrafficStats.getUidTxBytes(uid)
                assertTrue("IDLE_BACKGROUND_SERVICE_DIED", serviceExists(context))
                assertEquals(ProxyStatus.RUNNING, AppRuntime.state.value.status)
                assertEquals(0L, after.bytesSent - before.bytesSent)
                assertEquals(0L, after.bytesReceived - before.bytesReceived)
                assertEquals(0, after.activeConnections)
                val countersAvailable = listOf(rx, tx, rxAfter, txAfter).all { it >= 0 }
                if (countersAvailable) {
                    assertTrue("IDLE_UNSOLICITED_RX", rxAfter - rx in 0L..16_384L)
                    assertTrue("IDLE_UNSOLICITED_TX", txAfter - tx in 0L..16_384L)
                }
                val result = JSONObject().put("actualProductionService", true).put("homeBackgroundSeconds", 20)
                    .put("noTelegramPeer", true).put("payloadBytesSent", after.bytesSent - before.bytesSent)
                    .put("payloadBytesReceived", after.bytesReceived - before.bytesReceived)
                    .put("uidCountersAvailable", countersAvailable)
                    .put("uidRxDelta", if (countersAvailable) rxAfter - rx else JSONObject.NULL)
                    .put("uidTxDelta", if (countersAvailable) txAfter - tx else JSONObject.NULL)
                    .put("backgroundServiceAlive", true).put("dozeOrPhysicalOemTested", false)
                instrumentation.sendStatus(0, Bundle().apply {
                    putString("tgproxy_receipt_name", "idle-background-traffic")
                    putString("tgproxy_receipt_json", result.toString())
                })
            } finally {
                scenario.onActivity { it.stopService(Intent(it, ProxyService::class.java)) }
                waitUntil("IDLE_STOP_TIMEOUT") { !serviceExists(context) && AppRuntime.state.value.status == ProxyStatus.STOPPED }
                scenario.onActivity { AppRuntime.save(previous!!.ui()) }
                waitUntil("IDLE_RESTORE_TIMEOUT") { !AppRuntime.state.value.isSaving && AppRuntime.state.value.settings == previous!!.ui() }
                assertTrue("IDLE_RESTORE_EXACT_CIPHER", prefs.edit().putString("encrypted_v1", cipher).commit())
                assertEquals(previous!!.secretHex, store.load()?.secretHex)
            }
        }
    }
}
