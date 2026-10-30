package io.github.byshadow64.tgproxy

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

@RunWith(AndroidJUnit4::class)
class RegistryIdentityStoreTest {
    @Test fun installKeysAreStableNonExportableP256AndSeparateAcrossInstallAliases() {
        val firstAlias = "tgproxy.test.registry.a.${System.nanoTime()}"
        val secondAlias = "tgproxy.test.registry.b.${System.nanoTime()}"
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        try {
            val first = RegistryDeviceIdentityProvider(firstAlias)
            val public = first.publicKeySpki()
            assertArrayEquals(public, RegistryDeviceIdentityProvider(firstAlias).publicKeySpki())
            assertFalse(MessageDigest.isEqual(public, RegistryDeviceIdentityProvider(secondAlias).publicKeySpki()))
            val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(public)) as java.security.interfaces.ECPublicKey
            assertEquals(256, key.params.curve.field.fieldSize)
            val message = "synthetic-device-proof-only".toByteArray()
            assertTrue(Signature.getInstance("SHA256withECDSA").run { initVerify(key); update(message); verify(first.sign(message)) })
            assertNull(store.getKey(firstAlias, null).encoded)
            assertFalse(first.toString().contains(firstAlias))
        } finally { store.deleteEntry(firstAlias); store.deleteEntry(secondAlias) }
    }

    @Test fun registryEndpointRoundTripsEncryptedWithoutBearerLease() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val name = "tgproxy.test.registry.store.${System.nanoTime()}"
        val alias = "$name.aes"
        try {
            val store = SecureSettingsStore(context, alias, name)
            val settings = AppSettings(1443, "ab".repeat(16), true, "192.0.2.10", 8444, "cd".repeat(32), "", true)
            store.save(settings)
            val restored = store.load()!!
            assertTrue(restored.helperRegistryManaged); assertEquals("", restored.helperToken)
            assertEquals(settings.ui(), restored.ui())
            val ciphertext = context.getSharedPreferences(name, 0).getString("encrypted_v1", null)!!
            assertFalse(ciphertext.contains(settings.helperHost)); assertFalse(ciphertext.contains(settings.secretHex))
        } finally {
            context.deleteSharedPreferences(name)
            KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(alias) }
        }
    }
}
