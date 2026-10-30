package io.github.byshadow64.tgproxy

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class StoreException : Exception("SECURE_SETTINGS_UNAVAILABLE")

/** Codec enforces that managed registry settings contain no short-lived bearer lease. */
class SecureSettingsStore(context: Context, private val alias: String = "tgproxy.android.settings.v1", prefsName: String = "tgproxy.private.settings") {
    private val prefs = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
    private fun key(create: Boolean): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        if (!create) throw StoreException()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).setRandomizedEncryptionRequired(true).build())
        }.generateKey()
    }
    @Synchronized fun load(): AppSettings? {
        try {
            val saved = prefs.getString("encrypted_v1", null) ?: return null
            if (saved.length > 12000) throw StoreException()
            val plaintext = SettingsEncryption.decrypt(Base64.decode(saved, Base64.NO_WRAP), key(false))
            try { return SettingsCodec.decode(plaintext) } finally { plaintext.fill(0) }
        } catch (_: Exception) { throw StoreException() }
    }
    @Synchronized fun save(settings: AppSettings) {
        try {
            val plaintext = SettingsCodec.encode(settings)
            val encrypted = try { SettingsEncryption.encrypt(plaintext, key(true)) } finally { plaintext.fill(0) }
            if (!prefs.edit().putString("encrypted_v1", Base64.encodeToString(encrypted, Base64.NO_WRAP)).commit()) throw StoreException()
        } catch (_: Exception) { throw StoreException() }
    }
}
