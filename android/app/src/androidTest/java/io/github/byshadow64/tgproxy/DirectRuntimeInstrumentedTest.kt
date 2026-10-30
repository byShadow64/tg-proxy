package io.github.byshadow64.tgproxy

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.core.content.ContextCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.byshadow64.tgproxy.ui.ProxyStatus
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.concurrent.TimeUnit

/** Explicit anonymous network probe of the actual saved config/service; no injected engine/route. */
@RunWith(AndroidJUnit4::class)
class DirectRuntimeInstrumentedTest {
    private fun waitUntil(code: String, block: () -> Boolean) {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
        while (System.nanoTime() < end) { if (block()) return; Thread.sleep(40) }
        assertTrue(code, block())
    }
    @Suppress("DEPRECATION")
    private fun serviceExists(context: Context) = context.getSystemService(ActivityManager::class.java)
        .getRunningServices(Int.MAX_VALUE).any { it.service.className == ProxyService::class.java.name }

    @Test fun helperOffAutomaticRoutesReturnAnonymousResPqAndStop() {
        assumeTrue("Explicit public network probe only", InstrumentationRegistry.getArguments().getString("directPublicProbe") == "1")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val store = SecureSettingsStore(context)
        val prefs = context.getSharedPreferences("tgproxy.private.settings", 0)
        val before = store.load()
        assertTrue("DIRECT_PREVIOUS_SETTINGS_REQUIRED", before != null)
        val cipher = prefs.getString("encrypted_v1", null)
        val rows = JSONArray()
        var restored = false
        var listenerClosed = false
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { it.stopService(Intent(it, ProxyService::class.java)) }
            waitUntil("DIRECT_STOP_BARRIER") { AppRuntime.state.value.hasSavedSettings && !AppRuntime.state.value.isSaving &&
                AppRuntime.state.value.status == ProxyStatus.STOPPED && !serviceExists(context) }
            try {
                scenario.onActivity { AppRuntime.save(before!!.ui().copy(helperEnabled = false)) }
                waitUntil("DIRECT_SAVE_TIMEOUT") { !AppRuntime.state.value.isSaving && !AppRuntime.state.value.settings.helperEnabled }
                assertTrue("DIRECT_SAVED_HELPER_NOT_OFF", store.load()?.helperEnabled == false)
                scenario.onActivity { ContextCompat.startForegroundService(it, Intent(it, ProxyService::class.java).setAction(ProxyService.ACTION_START)) }
                waitUntil("DIRECT_START_TIMEOUT") { AppRuntime.state.value.status == ProxyStatus.RUNNING }
                val attempts = if (InstrumentationRegistry.getArguments().getString("directDiagnosticReconnect") == "1") 2 else 1
                val cases = if (InstrumentationRegistry.getArguments().getString("directAllDataCenters") == "1")
                    (1..5).flatMap { dc -> listOf(dc to false, dc to true) }
                else listOf(2 to false, 4 to false, 2 to true, 4 to true)
                for ((dc, media) in cases) repeat(attempts) { attempt ->
                    val started = System.nanoTime()
                    val beforeMetrics = AppRuntime.state.value.metrics
                    val journalStart = AppRuntime.state.value.journal.lastOrNull()?.id ?: 0
                    var matched = false
                    var failure = "NONE"
                    try {
                        LivePairingRuntimeInstrumentedTest().anonymousReqPq(before!!.port, before.secretHex, dc, media)
                        matched = true
                    } catch (_: java.net.SocketTimeoutException) { failure = "TIMEOUT" }
                    catch (_: java.io.EOFException) { failure = "EOF" }
                    catch (e: Exception) { failure = e.javaClass.simpleName }
                    Thread.sleep(40)
                    rows.put(JSONObject().put("dc", dc).put("media", media).put("resPqNonceMatched", matched)
                        .put("attempt", attempt + 1).put("elapsedMs", TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)).put("failure", failure)
                        .put("directConnectionsBefore", beforeMetrics.directConnections).put("directConnectionsAfter", AppRuntime.state.value.metrics.directConnections)
                        .put("helperConnectionsAfter", AppRuntime.state.value.metrics.helperConnections)
                        .put("safeJournal", JSONArray(AppRuntime.state.value.journal.filter { it.id > journalStart }.map { it.message })))
                }
                waitUntil("DIRECT_COUNTERS_MISSING") { AppRuntime.state.value.metrics.directConnections > 0 &&
                    AppRuntime.state.value.metrics.helperConnections == 0L && AppRuntime.state.value.metrics.bytesReceived > 0 }
            } finally {
                scenario.onActivity { it.stopService(Intent(it, ProxyService::class.java)) }
                waitUntil("DIRECT_STOP_TIMEOUT") { AppRuntime.state.value.status == ProxyStatus.STOPPED && !serviceExists(context) }
                ServerSocket().use { it.reuseAddress = true; it.bind(InetSocketAddress("127.0.0.1", before!!.port)) }
                listenerClosed = true
                scenario.onActivity { AppRuntime.save(before!!.ui()) }
                waitUntil("DIRECT_RESTORE_TIMEOUT") { !AppRuntime.state.value.isSaving && AppRuntime.state.value.settings == before!!.ui() }
                assertTrue("DIRECT_RESTORE_CIPHER", prefs.edit().putString("encrypted_v1", cipher).commit())
                restored = store.load()?.secretHex == before!!.secretHex
                val result = JSONObject().put("actualProductionService", true).put("helperOff", true)
                    .put("defaultAutomaticRoute", true).put("routeFactoryInjected", false).put("cases", rows)
                    .put("previousSettingsRestored", restored).put("stoppedListenerClosed", listenerClosed)
                    .put("accountOrCredentialsUsed", false)
                instrumentation.sendStatus(0, Bundle().apply {
                    putString("tgproxy_receipt_name", "direct-runtime-result"); putString("tgproxy_receipt_json", result.toString())
                })
            }
        }
        assertTrue("DIRECT_AUTOMATIC_CASE_FAILED", (0 until rows.length()).all { rows.getJSONObject(it).getBoolean("resPqNonceMatched") })
        assertTrue("DIRECT_RESTORE_FAILED", restored && listenerClosed)
    }
}
