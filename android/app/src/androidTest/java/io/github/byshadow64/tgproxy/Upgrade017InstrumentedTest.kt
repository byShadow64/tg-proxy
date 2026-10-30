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

/** Original code8 -> final code9: retain ciphertext, settings and the installation key. */
@RunWith(AndroidJUnit4::class)
class Upgrade017InstrumentedTest {
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
    @Test fun prepareOriginal016Profile() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("upgrade017Phase") == "prepare")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("UPGRADE017_REQUIRES_ORIGINAL_016", 8L, version(context))
        assertEquals("UPGRADE017_REQUIRES_EXACT_ORIGINAL_APK",
            "538f9bdbc2353ca904b867da84626238aa12cbf640011322dc39c09631e80335", apkHash(context))
        ActivityScenario.launch(MainActivity::class.java).use {
            Thread.sleep(500)
            assertNotNull("UPGRADE017_PROFILE_REQUIRED", SecureSettingsStore(context).load())
            val baseline = snapshot(context)
            File(context.filesDir, "upgrade017-baseline.json").writeText(baseline.toString())
            emit("upgrade017-baseline", baseline)
        }
    }
    @Test fun verifyCode9PreservesExactPrivateProfileAndDeviceKey() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("upgrade017Phase") == "verify")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("UPGRADE017_REQUIRES_CODE9", 9L, version(context))
        assertEquals("0.1.7-dev", context.packageManager.getPackageInfo(context.packageName, 0).versionName)
        val baseline = JSONObject(File(context.filesDir, "upgrade017-baseline.json").readText())
        ActivityScenario.launch(MainActivity::class.java).use {
            val now = snapshot(context)
            for (field in listOf("ciphertextSha256", "settingsSha256", "secretSha256", "registryPublicKeySha256", "localPort", "helperRegistryManaged"))
                assertEquals("UPGRADE017_CHANGED_$field", baseline.get(field), now.get(field))
            val settings = SecureSettingsStore(context).load()!!
            if (settings.helperRegistryManaged) assertTrue("UPGRADE017_BEARER_PERSISTED", settings.helperToken.isEmpty())
            now.put("preserved", true).put("originalPreviousRelease", true).put("privateFixture", false)
            emit("upgrade017-verified", now)
        }
    }
}
