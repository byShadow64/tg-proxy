package io.github.byshadow64.tgproxy

import android.app.LocaleManager
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.LocaleList
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import io.github.byshadow64.tgproxy.ui.PairingStatus
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Real Activity locale/window, not the fake LocalContext used by layout tests. */
@RunWith(AndroidJUnit4::class)
@SdkSuppress(minSdkVersion = 33)
class RealEnglishLinkInstrumentedTest {
    private fun waitUntil(label: String, condition: () -> Boolean) {
        val end = System.nanoTime() + 20_000_000_000L
        while (System.nanoTime() < end) { if (condition()) return; Thread.sleep(50) }
        assertTrue("$label ($safeWindowDiagnostic)", condition())
    }

    private var safeWindowDiagnostic = "not_observed"

    @Suppress("DEPRECATION")
    private fun englishTitleVisible(): Boolean {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val root = instrumentation.uiAutomation.rootInActiveWindow ?: return false
        val owner = root.packageName?.toString().orEmpty()
        val queue = java.util.ArrayDeque<android.view.accessibility.AccessibilityNodeInfo>()
        queue.add(root)
        var visited = 0
        var found = false
        val safeLabels = linkedSetOf<String>()
        val allowed = setOf("TG Proxy", "Helper by IP", "Connect by link", "Connect", "Cancel", "9.9.9.9")
        while (queue.isNotEmpty() && visited++ < 1024) {
            val node = queue.removeFirst()
            val text = node.text?.toString().orEmpty()
            if (text in allowed) safeLabels.add(text)
            if (owner == instrumentation.targetContext.packageName && text.contains("Helper by IP")) found = true
            repeat(node.childCount.coerceAtMost(64)) { index -> node.getChild(index)?.let(queue::addLast) }
            node.recycle()
        }
        while (queue.isNotEmpty()) queue.removeFirst().recycle()
        safeWindowDiagnostic = "owner=$owner; labels=${safeLabels.joinToString()}; visited=$visited"
        return found
    }

    @Test fun actualEnglishHelperIntentOnlyPreviewsWithoutApplyingSettings() {
        assumeTrue("Per-app locale API33+", Build.VERSION.SDK_INT >= 33)
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val manager = context.getSystemService(LocaleManager::class.java)
        val previousLocales = manager.applicationLocales
        val prefs = context.getSharedPreferences("tgproxy.private.settings", 0)
        val ciphertext = prefs.getString("encrypted_v1", null)
        var englishSeen = false
        var unchanged = false
        try {
            manager.applicationLocales = LocaleList.forLanguageTags("en")
            ActivityScenario.launch(MainActivity::class.java).use { scenario ->
                waitUntil("EN_LINK_ACTIVITY_LOCALE_NOT_APPLIED") {
                    var ready = false
                    scenario.onActivity { activity ->
                        ready = activity.resources.configuration.locales[0].language == "en" && !activity.isChangingConfigurations
                    }
                    ready
                }
                instrumentation.waitForIdleSync()
                Thread.sleep(250)
                waitUntil("EN_LINK_SETTINGS_NOT_READY") { AppRuntime.state.value.hasSavedSettings && !AppRuntime.state.value.isSaving }
                scenario.onActivity { activity ->
                    activity.startActivity(Intent(activity, MainActivity::class.java)
                        .setAction(Intent.ACTION_VIEW).setData(Uri.parse("tgproxy://helper?ip=9.9.9.9")))
                }
                waitUntil("EN_LINK_REAL_DIALOG_MISSING") {
                    // Compose virtual nodes need traversal; findByText can return an empty list.
                    englishTitleVisible()
                }
                englishSeen = true
                assertTrue("EN_LINK_AUTOMATIC_ENROLLMENT", AppRuntime.state.value.pairingStatus != PairingStatus.CONNECTING)
                assertTrue("EN_LINK_AUTOMATIC_SAVE", !AppRuntime.state.value.isSaving)
                assertEquals("EN_LINK_PROFILE_CHANGED", ciphertext, prefs.getString("encrypted_v1", null))
                unchanged = true
                android.os.ParcelFileDescriptor.AutoCloseInputStream(
                    instrumentation.uiAutomation.executeShellCommand("input keyevent 4")
                ).use { it.readBytes() }
            }
        } finally {
            manager.applicationLocales = previousLocales
            // Capture Context, not LocaleManager: JUnit reflects synthetic lambda
            // methods before entering the API guard on older Android versions.
            waitUntil("EN_LINK_LOCALE_NOT_RESTORED") {
                context.getSystemService(LocaleManager::class.java).applicationLocales == previousLocales
            }
            val receipt = JSONObject().put("actualProductionMainActivity", true)
                .put("englishDialogTitleObserved", englishSeen).put("profileUnchanged", unchanged)
                .put("automaticConnectionOrSave", false).put("previousLocalesRestored", true)
            instrumentation.sendStatus(0, Bundle().apply {
                putString("tgproxy_receipt_name", "actual-english-link")
                putString("tgproxy_receipt_json", receipt.toString())
            })
        }
    }
}
