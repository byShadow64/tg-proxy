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

/** Original code11 -> final code12: retain ciphertext, settings and the installation key. */
@RunWith(AndroidJUnit4::class)
class Upgrade020InstrumentedTest {
    private val originalApkSha256 = "6faef05e1934c068ae5e5355cbcae9e4e93214865621be790c0739e34c221c8d"
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
    @Test fun prepareOriginal019Profile() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("upgrade020Phase") == "prepare")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("UPGRADE020_REQUIRES_ORIGINAL_019", 11L, version(context))
        assertEquals("0.1.9-dev", context.packageManager.getPackageInfo(context.packageName, 0).versionName)
        assertEquals("UPGRADE020_REQUIRES_EXACT_ORIGINAL_APK", originalApkSha256, apkHash(context))
        ActivityScenario.launch(MainActivity::class.java).use {
            Thread.sleep(500)
            assertNotNull("UPGRADE020_PROFILE_REQUIRED", SecureSettingsStore(context).load())
            val baseline = snapshot(context).put("originalApkSha256", originalApkSha256)
            File(context.filesDir, "upgrade020-baseline.json").writeText(baseline.toString())
            emit("upgrade020-baseline", baseline)
        }
    }
    @Test fun verifyCode12PreservesExactPrivateProfileAndDeviceKey() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("upgrade020Phase") == "verify")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("UPGRADE020_REQUIRES_CODE12", 12L, version(context))
        assertEquals("0.1.10-dev", context.packageManager.getPackageInfo(context.packageName, 0).versionName)
        val finalHash = InstrumentationRegistry.getArguments().getString("expectedFinalApkSha256")!!
        assertTrue("UPGRADE020_EXACT_FINAL_HASH_REQUIRED", finalHash.matches(Regex("[0-9a-f]{64}")))
        assertEquals("UPGRADE020_REQUIRES_EXACT_FINAL_APK", finalHash, apkHash(context))
        val baseline = JSONObject(File(context.filesDir, "upgrade020-baseline.json").readText())
        assertEquals("UPGRADE020_REQUIRES_CODE11_BASELINE", 11L, baseline.getLong("versionCode"))
        assertEquals("UPGRADE020_REQUIRES_ORIGINAL_BASELINE", originalApkSha256, baseline.getString("originalApkSha256"))
        ActivityScenario.launch(MainActivity::class.java).use {
            val now = snapshot(context)
            for (field in listOf("ciphertextSha256", "settingsSha256", "secretSha256", "registryPublicKeySha256", "localPort", "helperRegistryManaged"))
                assertEquals("UPGRADE020_CHANGED_$field", baseline.get(field), now.get(field))
            val settings = SecureSettingsStore(context).load()!!
            if (settings.helperRegistryManaged) assertTrue("UPGRADE020_BEARER_PERSISTED", settings.helperToken.isEmpty())
            now.put("preserved", true).put("originalPreviousRelease", true).put("privateFixture", false)
            emit("upgrade020-verified", now)
        }
    }
}

