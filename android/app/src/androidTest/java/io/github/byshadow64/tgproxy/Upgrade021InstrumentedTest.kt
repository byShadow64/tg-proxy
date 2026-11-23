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

/** Original code12 -> final code13: retain ciphertext, settings and the installation key. */
@RunWith(AndroidJUnit4::class)
class Upgrade021InstrumentedTest {
    private val originalApkSha256 = "9126515996bd0cbc5852d19b01ff83bd8f70971c44a70ddf57d2e5d2c1c2cee0"
    private fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun version(context: Context): Long {
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        return if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else @Suppress("DEPRECATION") info.versionCode.toLong()
    }
    private fun apkHash(context: Context): String {
        val digest = MessageDigest.getInstance("SHA-256")
        File(context.applicationInfo.sourceDir).inputStream().use { input ->
            val buffer = ByteArray(65536)
            while (true) { val count = input.read(buffer); if (count < 0) break; if (count > 0) digest.update(buffer, 0, count) }
        }
        return digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
    }
    private fun snapshot(context: Context): JSONObject {
        val settings = SecureSettingsStore(context).load()!!
        val ciphertext = context.getSharedPreferences("tgproxy.private.settings", 0).getString("encrypted_v1", null)!!
        val encoded = SettingsCodec.encode(settings)
        return try {
            JSONObject().put("versionCode", version(context))
                .put("ciphertextSha256", hash(ciphertext.toByteArray()))
                .put("settingsSha256", hash(encoded)).put("secretSha256", hash(settings.secretHex.toByteArray()))
                .put("registryPublicKeySha256", hash(RegistryDeviceIdentityProvider().publicKeySpki()))
                .put("localPort", settings.port).put("helperRegistryManaged", settings.helperRegistryManaged)
                .put("ownedEmulatorProfile", true)
        } finally { encoded.fill(0) }
    }
    private fun emit(name: String, receipt: JSONObject) {
        InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
            putString("tgproxy_receipt_name", name); putString("tgproxy_receipt_json", receipt.toString())
        })
    }
    @Test fun prepareOriginal020Profile() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("upgrade021Phase") == "prepare")
        assumeTrue("Owned emulator only", Build.HARDWARE in setOf("ranchu", "goldfish"))
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("UPGRADE021_REQUIRES_ORIGINAL_020", 12L, version(context))
        assertEquals("0.1.10-dev", context.packageManager.getPackageInfo(context.packageName, 0).versionName)
        assertEquals("UPGRADE021_REQUIRES_EXACT_ORIGINAL_APK", originalApkSha256, apkHash(context))
        // Keep this owned-emulator verification entirely away from production update endpoints.
        val updates = context.getSharedPreferences("verified_updates", Context.MODE_PRIVATE)
        val policy = JSONObject().put("automatic", updates.getBoolean("automatic", true))
            .put("wifi", updates.getBoolean("wifi", true))
        File(context.filesDir, "upgrade021-update-policy.json").writeText(policy.toString())
        assertTrue(updates.edit().putBoolean("automatic", false).putBoolean("wifi", false).commit())
        ActivityScenario.launch(MainActivity::class.java).use {
            Thread.sleep(500)
            assertNotNull("UPGRADE021_PROFILE_REQUIRED", SecureSettingsStore(context).load())
            val baseline = snapshot(context).put("originalApkSha256", originalApkSha256)
            File(context.filesDir, "upgrade021-baseline.json").writeText(baseline.toString())
            emit("upgrade021-baseline", baseline)
        }
    }
    @Test fun verifyCode13PreservesExactPrivateProfileAndDeviceKey() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("upgrade021Phase") == "verify")
        assumeTrue("Owned emulator only", Build.HARDWARE in setOf("ranchu", "goldfish"))
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("UPGRADE021_REQUIRES_CODE13", 13L, version(context))
        assertEquals("0.1.11-dev", context.packageManager.getPackageInfo(context.packageName, 0).versionName)
        val finalHash = InstrumentationRegistry.getArguments().getString("expectedFinalApkSha256")!!
        assertTrue("UPGRADE021_EXACT_FINAL_HASH_REQUIRED", finalHash.matches(Regex("[0-9a-f]{64}")))
        assertEquals("UPGRADE021_REQUIRES_EXACT_FINAL_APK", finalHash, apkHash(context))
        val baseline = JSONObject(File(context.filesDir, "upgrade021-baseline.json").readText())
        assertEquals("UPGRADE021_REQUIRES_CODE12_BASELINE", 12L, baseline.getLong("versionCode"))
        assertEquals("UPGRADE021_REQUIRES_ORIGINAL_BASELINE", originalApkSha256, baseline.getString("originalApkSha256"))
        assertFalse("UPGRADE021_AUTO_CHECK_MUST_STAY_DISABLED_DURING_TESTS", context.getSharedPreferences("verified_updates", Context.MODE_PRIVATE).getBoolean("automatic", true))
        ActivityScenario.launch(MainActivity::class.java).use {
            val now = snapshot(context)
            for (field in listOf("ciphertextSha256", "settingsSha256", "secretSha256", "registryPublicKeySha256", "localPort", "helperRegistryManaged"))
                assertEquals("UPGRADE021_CHANGED_$field", baseline.get(field), now.get(field))
            val settings = SecureSettingsStore(context).load()!!
            if (settings.helperRegistryManaged) assertTrue("UPGRADE021_BEARER_PERSISTED", settings.helperToken.isEmpty())
            now.put("preserved", true).put("originalPreviousRelease", true).put("privateFixture", false)
            emit("upgrade021-verified", now)
        }
    }
    @Test fun restoreOwnedEmulatorUpdatePolicy() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("upgrade021Phase") == "restore")
        assumeTrue("Owned emulator only", Build.HARDWARE in setOf("ranchu", "goldfish"))
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val file = File(context.filesDir, "upgrade021-update-policy.json")
        val policy = JSONObject(file.readText())
        assertTrue(context.getSharedPreferences("verified_updates", Context.MODE_PRIVATE).edit()
            .putBoolean("automatic", policy.getBoolean("automatic"))
            .putBoolean("wifi", policy.getBoolean("wifi")).commit())
        file.delete()
    }
}
