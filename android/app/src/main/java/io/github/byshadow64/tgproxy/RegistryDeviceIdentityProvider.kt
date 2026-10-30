package io.github.byshadow64.tgproxy

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.github.byshadow64.tgproxy.core.RegistryDeviceIdentity
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/** Per-install non-exportable P-256 key. No hardware IDs, owner credentials or attestation are requested. */
class RegistryDeviceIdentityProvider(private val alias: String = "tgproxy.android.registry.device.v1") : RegistryDeviceIdentity {
    @Synchronized private fun entry(): KeyStore.PrivateKeyEntry {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!store.containsAlias(alias)) {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
                initialize(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256).setUserAuthenticationRequired(false).build())
            }.generateKeyPair()
        }
        return store.getEntry(alias, null) as KeyStore.PrivateKeyEntry
    }
    override fun publicKeySpki(): ByteArray = entry().certificate.publicKey.encoded.copyOf()
    override fun sign(message: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSA").run {
        initSign(entry().privateKey); update(message); sign()
    }
    override fun toString() = "RegistryDeviceIdentityProvider(<private>)"
}
