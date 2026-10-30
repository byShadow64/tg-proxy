package io.github.byshadow64.tgproxy

import android.content.Context
import android.os.Build
import android.os.Bundle
import android.util.Base64
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom

/** Explicit two-phase fixture for an owned emulator; neither method prints credentials. */
@RunWith(AndroidJUnit4::class)
class UpgradePersistenceInstrumentedTest {
    private fun emitReceipt(name: String, value: JSONObject) {
        InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
            putString("tgproxy_receipt_name", name)
            putString("tgproxy_receipt_json", value.toString())
        })
    }
    private fun requirePhase(phase: String) = org.junit.Assume.assumeTrue(
        "Explicit two-phase upgrade fixture only",
        InstrumentationRegistry.getArguments().getString("upgradePhase") == phase,
    )
    private fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 255) }

    private fun version(context: Context): Long {
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        return if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else @Suppress("DEPRECATION") info.versionCode.toLong()
    }

    private fun snapshot(context: Context): JSONObject {
        val settings = SecureSettingsStore(context).load()
        assertTrue("UPGRADE_SETTINGS_MISSING", settings != null)
        val encrypted = context.getSharedPreferences("tgproxy.private.settings", Context.MODE_PRIVATE)
            .getString("encrypted_v1", null)
        assertTrue("UPGRADE_CIPHERTEXT_MISSING", encrypted != null)
        val encoded = SettingsCodec.encode(settings!!)
        return try {
            JSONObject().put("versionCode", version(context))
                .put("ciphertextSha256", digest(Base64.decode(encrypted, Base64.NO_WRAP)))
                .put("settingsSha256", digest(encoded))
                .put("secretSha256", digest(settings.secretHex.toByteArray(Charsets.UTF_8)))
                .put("localPort", settings.port)
                .put("syntheticFixture", true)
        } finally { encoded.fill(0) }
    }

    @Test fun prepareBaseline() {
        requirePhase("prepare")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue("UPGRADE_PREPARATION_REQUIRES_ORIGINAL_CODE1", version(context) == 1L)
        val random = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val secret = random.joinToString("") { "%02x".format(it.toInt() and 255) }
        random.fill(0)
        SecureSettingsStore(context).save(AppSettings(35443, secret, true, "upgrade-fixture.invalid", 8444,
            "a1".repeat(32), "synthetic-upgrade-token-".repeat(2)))
        val baseline = snapshot(context)
        File(context.filesDir, "upgrade-baseline.json").writeText(baseline.toString(2))
        emitReceipt("upgrade-baseline", baseline)
    }

    @Test fun verifyUpgradedProfile() {
        requirePhase("verify")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val baselineFile = File(context.filesDir, "upgrade-baseline.json")
        assertTrue("UPGRADE_BASELINE_MISSING", baselineFile.isFile)
        assertTrue("UPGRADE_REQUIRES_CODE2", version(context) == 2L)
        val baseline = JSONObject(baselineFile.readText())
        ActivityScenario.launch(MainActivity::class.java).use {
            val current = snapshot(context)
            for (key in listOf("ciphertextSha256", "settingsSha256", "secretSha256", "localPort")) {
                assertTrue("UPGRADE_PROFILE_CHANGED_$key", baseline.get(key) == current.get(key))
            }
            assertTrue("UPGRADE_UI_PORT_CHANGED", AppRuntime.state.value.settings.localPort == current.getInt("localPort").toString())
            current.put("preserved", true)
            File(context.filesDir, "upgrade-verified.json").writeText(current.toString(2))
            emitReceipt("upgrade-verified", current)
        }
    }
}
