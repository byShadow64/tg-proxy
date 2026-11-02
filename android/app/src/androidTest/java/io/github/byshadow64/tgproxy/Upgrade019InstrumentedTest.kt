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

/** Original code10 -> final code11: retain ciphertext, settings and the installation key. */
@RunWith(AndroidJUnit4::class)
class Upgrade019InstrumentedTest {
    private val originalApkSha256 = "f6770749d14f7a8637e35f7ebe29c8513938f16aab56e287e7c2163d2fadc8d2"
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
    @Test fun prepareOriginal018Profile() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("upgrade019Phase") == "prepare")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("UPGRADE019_REQUIRES_ORIGINAL_018", 10L, version(context))
        assertEquals("0.1.8-dev", context.packageManager.getPackageInfo(context.packageName, 0).versionName)
        assertEquals("UPGRADE019_REQUIRES_EXACT_ORIGINAL_APK", originalApkSha256, apkHash(context))
        ActivityScenario.launch(MainActivity::class.java).use {
            Thread.sleep(500)
            assertNotNull("UPGRADE019_PROFILE_REQUIRED", SecureSettingsStore(context).load())
            val baseline = snapshot(context).put("originalApkSha256", originalApkSha256)
            File(context.filesDir, "upgrade019-baseline.json").writeText(baseline.toString())
            emit("upgrade019-baseline", baseline)
        }
    }
    @Test fun verifyCode11PreservesExactPrivateProfileAndDeviceKey() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("upgrade019Phase") == "verify")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("UPGRADE019_REQUIRES_CODE11", 11L, version(context))
        assertEquals("0.1.9-dev", context.packageManager.getPackageInfo(context.packageName, 0).versionName)
        val finalHash = InstrumentationRegistry.getArguments().getString("expectedFinalApkSha256")!!
        assertTrue("UPGRADE019_EXACT_FINAL_HASH_REQUIRED", finalHash.matches(Regex("[0-9a-f]{64}")))
        assertEquals("UPGRADE019_REQUIRES_EXACT_FINAL_APK", finalHash, apkHash(context))
        val baseline = JSONObject(File(context.filesDir, "upgrade019-baseline.json").readText())
        assertEquals("UPGRADE019_REQUIRES_CODE10_BASELINE", 10L, baseline.getLong("versionCode"))
        assertEquals("UPGRADE019_REQUIRES_ORIGINAL_BASELINE", originalApkSha256, baseline.getString("originalApkSha256"))
        ActivityScenario.launch(MainActivity::class.java).use {
            val now = snapshot(context)
            for (field in listOf("ciphertextSha256", "settingsSha256", "secretSha256", "registryPublicKeySha256", "localPort", "helperRegistryManaged"))
                assertEquals("UPGRADE019_CHANGED_$field", baseline.get(field), now.get(field))
            val settings = SecureSettingsStore(context).load()!!
            if (settings.helperRegistryManaged) assertTrue("UPGRADE019_BEARER_PERSISTED", settings.helperToken.isEmpty())
            now.put("preserved", true).put("originalPreviousRelease", true).put("privateFixture", false)
            emit("upgrade019-verified", now)
        }
    }
}

