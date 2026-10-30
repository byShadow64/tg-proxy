package io.github.byshadow64.tgproxy

import android.content.Context
import android.os.Build
import android.os.Bundle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest

/** Exact original code5 -> final code6, with no uninstall, clear, or profile output. */
@RunWith(AndroidJUnit4::class)
class Upgrade015InstrumentedTest {
    private fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun version(context: Context): Long {
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        return if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else @Suppress("DEPRECATION") info.versionCode.toLong()
    }
    private fun snapshot(context: Context): JSONObject {
        val settings = SecureSettingsStore(context).load()!!
        val ciphertext = context.getSharedPreferences("tgproxy.private.settings", 0).getString("encrypted_v1", null)!!
        val encoded = SettingsCodec.encode(settings)
        return try {
            JSONObject().put("versionCode", version(context))
                .put("ciphertextSha256", hash(ciphertext.toByteArray()))
                .put("settingsSha256", hash(encoded)).put("secretSha256", hash(settings.secretHex.toByteArray()))
                .put("localPort", settings.port).put("helperRegistryManaged", settings.helperRegistryManaged)
                .put("ownedEmulatorProfile", true)
        } finally { encoded.fill(0) }
    }
    private fun emit(name: String, receipt: JSONObject) {
        InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
            putString("tgproxy_receipt_name", name); putString("tgproxy_receipt_json", receipt.toString())
        })
    }
    @Test fun prepareOriginal014Profile() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("upgrade015Phase") == "prepare")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("UPGRADE015_REQUIRES_ORIGINAL_014", 5L, version(context))
        ActivityScenario.launch(MainActivity::class.java).use {
            Thread.sleep(500)
            assertNotNull("UPGRADE015_PROFILE_REQUIRED", SecureSettingsStore(context).load())
            val baseline = snapshot(context)
            File(context.filesDir, "upgrade015-baseline.json").writeText(baseline.toString())
            emit("upgrade015-baseline", baseline)
        }
    }
    @Test fun verifyCode6PreservesExactPrivateProfile() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("upgrade015Phase") == "verify")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("UPGRADE015_REQUIRES_CODE6", 6L, version(context))
        val baseline = JSONObject(File(context.filesDir, "upgrade015-baseline.json").readText())
        ActivityScenario.launch(MainActivity::class.java).use {
            val now = snapshot(context)
            for (field in listOf("ciphertextSha256", "settingsSha256", "secretSha256", "localPort", "helperRegistryManaged"))
                assertEquals("UPGRADE015_CHANGED_$field", baseline.get(field), now.get(field))
            val settings = SecureSettingsStore(context).load()!!
            if (settings.helperRegistryManaged) assertTrue("UPGRADE015_BEARER_PERSISTED", settings.helperToken.isEmpty())
            now.put("preserved", true).put("originalPreviousRelease", true)
            emit("upgrade015-verified", now)
        }
    }
}
