package io.github.byshadow64.tgproxy

import android.content.Context
import android.os.Build
import android.os.Bundle
import android.util.Base64
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.SecretKey

/** Original code2 -> code3 only. Never clears/uninstalls or prints the existing private profile. */
@RunWith(AndroidJUnit4::class)
class Upgrade012InstrumentedTest {
    private fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun version(context: Context): Long {
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        return if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else @Suppress("DEPRECATION") info.versionCode.toLong()
    }
    private fun snapshot(context: Context): JSONObject {
        val settings = SecureSettingsStore(context).load()!!
        val ciphertext = context.getSharedPreferences("tgproxy.private.settings", 0).getString("encrypted_v1", null)!!
        // Serialize the original seven fields independently of the new TGP2 flag.
        val legacy = ByteArrayOutputStream().also { bytes -> DataOutputStream(bytes).use { out ->
            out.writeInt(0x54475031); out.writeInt(settings.port); out.writeUTF(settings.secretHex)
            out.writeBoolean(settings.helperEnabled); out.writeUTF(settings.helperHost); out.writeInt(settings.helperPort)
            out.writeUTF(settings.helperFingerprint); out.writeUTF(settings.helperToken)
        } }.toByteArray()
        return try { JSONObject().put("versionCode", version(context)).put("ciphertextSha256", hash(Base64.decode(ciphertext, Base64.NO_WRAP)))
            .put("originalSettingsSha256", hash(legacy)).put("secretSha256", hash(settings.secretHex.toByteArray()))
            .put("localPort", settings.port).put("ownedEmulatorProfile", true) } finally { legacy.fill(0) }
    }
    private fun emit(name: String, receipt: JSONObject) {
        InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
            putString("tgproxy_receipt_name", name); putString("tgproxy_receipt_json", receipt.toString())
        })
    }
    @Test fun prepareOriginal011Profile() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("upgrade012Phase") == "prepare")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("UPGRADE012_REQUIRES_ORIGINAL_011", 2L, version(context))
        ActivityScenario.launch(MainActivity::class.java).use {
            Thread.sleep(500)
            assertNotNull("UPGRADE012_ORIGINAL_PROFILE_REQUIRED", SecureSettingsStore(context).load())
            val baseline = snapshot(context)
            File(context.filesDir, "upgrade012-baseline.json").writeText(baseline.toString())
            emit("upgrade012-baseline", baseline)
        }
    }
    @Test fun verifyCode3AndTgp1MigrationPreservePrivateProfile() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("upgrade012Phase") == "verify")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("UPGRADE012_REQUIRES_CODE3", 3L, version(context))
        val baseline = JSONObject(File(context.filesDir, "upgrade012-baseline.json").readText())
        ActivityScenario.launch(MainActivity::class.java).use {
            val now = snapshot(context)
            for (field in listOf("ciphertextSha256", "originalSettingsSha256", "secretSha256", "localPort"))
                assertEquals("UPGRADE012_CHANGED_$field", baseline.get(field), now.get(field))
            val settings = SecureSettingsStore(context).load()!!
            assertFalse("UPGRADE012_INVENTED_REGISTRY_TRUST", settings.helperRegistryManaged)
            val original = context.getSharedPreferences("tgproxy.private.settings", 0).getString("encrypted_v1", null)!!
            val key = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getKey("tgproxy.android.settings.v1", null) as SecretKey
            val plain = SettingsEncryption.decrypt(Base64.decode(original, Base64.NO_WRAP), key)
            try {
                assertEquals(0x54475031, java.nio.ByteBuffer.wrap(plain).int)
                val migrated = SettingsCodec.encode(SettingsCodec.decode(plain))
                try {
                    assertEquals(0x54475032, java.nio.ByteBuffer.wrap(migrated).int)
                    val decoded = SettingsCodec.decode(migrated)
                    assertEquals(settings.ui(), decoded.ui()); assertEquals(settings.secretHex, decoded.secretHex)
                    assertFalse(decoded.helperRegistryManaged)
                } finally { migrated.fill(0) }
            } finally { plain.fill(0) }
            now.put("preserved", true).put("tgp1ReadAndTgp2EncodeVerified", true).put("privateModePreserved", true)
            emit("upgrade012-verified", now)
        }
    }
}
