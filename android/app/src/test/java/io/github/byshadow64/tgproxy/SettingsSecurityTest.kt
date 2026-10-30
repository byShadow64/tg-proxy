package io.github.byshadow64.tgproxy

import io.github.byshadow64.tgproxy.ui.ProxySettingsUi
import io.github.byshadow64.tgproxy.ui.SettingsFields
import org.junit.Assert.*
import org.junit.Test
import javax.crypto.KeyGenerator

class SettingsSecurityTest {
    private fun key() = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val secret = "0123456789abcdef0123456789abcdef"
    private val token = "synthetic-helper-token-do-not-use"
    private fun settings() = AppSettings(1443, secret, true, "helper.example.invalid", 8444, "ab".repeat(32), token)
    private fun rejects(block: () -> Unit) { try { block(); fail("Expected rejection") } catch (e: AssertionError) { throw e } catch (_: Exception) { } }
    @Test fun generatedSecretIsRandomAndCorrectSize() {
        val a = AppSettings.fresh(); val b = AppSettings.fresh()
        assertTrue(a.secretHex.matches(Regex("[0-9a-f]{32}")))
        assertNotEquals(a.secretHex, b.secretHex)
    }
    @Test fun settingsRoundTripPreservesFieldsAndHasNoTrailingData() {
        val s = settings(); val bytes = SettingsCodec.encode(s); val d = SettingsCodec.decode(bytes)
        assertEquals(s.secretHex, d.secretHex); assertEquals(s.ui(), d.ui())
        rejects { SettingsCodec.decode(bytes + byteArrayOf(1)) }
        rejects { SettingsCodec.decode(ByteArray(9000)) }
        rejects { SettingsCodec.decode(bytes.copyOf(12)) }
    }
    @Test fun aesGcmRoundTripAndRandomIv() {
        val k = key(); val plain = SettingsCodec.encode(settings())
        val a = SettingsEncryption.encrypt(plain, k); val b = SettingsEncryption.encrypt(plain, k)
        assertFalse(a.contentEquals(b)); assertArrayEquals(plain, SettingsEncryption.decrypt(a, k))
        for (s in listOf(secret, token, "helper.example.invalid")) assertFalse(String(a, Charsets.ISO_8859_1).contains(s))
    }
    @Test fun wrongKeyAndTamperedHeaderIvOrTagFailClosed() {
        val k = key(); val a = SettingsEncryption.encrypt(SettingsCodec.encode(settings()), k)
        rejects { SettingsEncryption.decrypt(a, key()) }
        for (index in listOf(0, 8, a.lastIndex)) {
            val changed = a.copyOf(); changed[index] = (changed[index].toInt() xor 1).toByte()
            rejects { SettingsEncryption.decrypt(changed, k) }
        }
    }
    @Test fun oversizeAndTruncatedCiphertextsAreRejected() {
        val k = key()
        rejects { SettingsEncryption.encrypt(ByteArray(8193), k) }
        rejects { SettingsEncryption.decrypt(ByteArray(9000), k) }
        rejects { SettingsEncryption.decrypt(ByteArray(31), k) }
    }
    @Test fun tokenAndSecretAreRedactedFromDebugRepresentations() {
        val s = settings()
        for (text in listOf(s.toString(), s.ui().toString(), s.engine().toString(), s.engine().helper.toString())) {
            assertFalse(text.contains(secret)); assertFalse(text.contains(token)); assertFalse(text.contains("helper.example.invalid"))
        }
    }
    @Test fun invalidPortsAreNotSavedAndSecretDoesNotChange() {
        val s = settings()
        for (port in listOf("0", "1023", "65536", "-1", "abc")) assertTrue(SettingsValidation.parse(s.ui().copy(localPort = port), s).errors.containsKey(SettingsFields.LOCAL_PORT))
        for (port in listOf("1024", "65535")) assertEquals(secret, SettingsValidation.parse(s.ui().copy(localPort = port), s).settings!!.secretHex)
    }
    @Test fun helperRejectsSchemesPathsCredentialsInvalidIpv6AndControlTokens() {
        val s = settings()
        for (host in listOf("https://helper.example.invalid", "host/path", "user@host", "bad host", "::::", "host?x=1")) assertTrue(host, SettingsValidation.parse(s.ui().copy(helperHost = host), s).errors.containsKey(SettingsFields.HELPER_HOST))
        for (t in listOf("", "x".repeat(31), "bad\ntoken", "x".repeat(513), "é".repeat(257))) assertTrue(SettingsValidation.parse(s.ui().copy(helperToken = t), s).errors.containsKey(SettingsFields.HELPER_TOKEN))
        for (t in listOf("x".repeat(32), "x".repeat(512), "é".repeat(256))) assertTrue(SettingsValidation.parse(s.ui().copy(helperToken = t), s).errors.isEmpty())
    }
    @Test fun certificateFingerprintIsNormalizedButNeverGuessed() {
        val s = settings()
        val good = SettingsValidation.parse(s.ui().copy(helperCertificateSha256 = List(32) { "AB" }.joinToString(":")), s)
        assertEquals("ab".repeat(32), good.settings!!.helperFingerprint)
        assertTrue(SettingsValidation.parse(s.ui().copy(helperCertificateSha256 = "wrong"), s).errors.containsKey(SettingsFields.HELPER_CERTIFICATE_SHA256))
        assertTrue(SettingsValidation.parse(s.ui().copy(helperHost = "::1"), s).errors.isEmpty())
    }
    @Test fun disabledHelperMayBeUnconfiguredAndDoesNotBecomePlaintextRoute() {
        val s = AppSettings(port = 1443, secretHex = secret)
        val result = SettingsValidation.parse(ProxySettingsUi(), s).settings!!
        assertNull(result.engine().helper)
        assertEquals(secret, SettingsCodec.decode(SettingsCodec.encode(result)).secretHex)
    }

    @Test fun registryModePersistsVerifiedEndpointButCannotPersistBearerLease() {
        val managed = AppSettings(1443, secret, true, "192.0.2.10", 8444, "ab".repeat(32), "", true)
        val decoded = SettingsCodec.decode(SettingsCodec.encode(managed))
        assertTrue(decoded.helperRegistryManaged); assertEquals("", decoded.helperToken)
        assertEquals(managed.ui(), decoded.ui()); assertEquals(secret, decoded.secretHex)
        assertTrue(SettingsValidation.parse(managed.ui().copy(helperToken = "TGL1." + "x".repeat(200)), managed).errors.containsKey(SettingsFields.HELPER_TOKEN))
        assertTrue(SettingsValidation.parse(managed.ui().copy(helperHost = "helper.example.invalid"), managed).errors.containsKey(SettingsFields.HELPER_HOST))
        assertTrue(SettingsValidation.parse(managed.ui().copy(helperRegistryManaged = false), managed).errors.containsKey(SettingsFields.HELPER_TOKEN))
    }

    @Test fun originalV1EncryptedPayloadMigratesWithoutInventingRegistryTrust() {
        val original = settings()
        val old = java.io.ByteArrayOutputStream().also { bytes -> java.io.DataOutputStream(bytes).use { out ->
            out.writeInt(0x54475031); out.writeInt(original.port); out.writeUTF(original.secretHex)
            out.writeBoolean(original.helperEnabled); out.writeUTF(original.helperHost); out.writeInt(original.helperPort)
            out.writeUTF(original.helperFingerprint); out.writeUTF(original.helperToken)
        } }.toByteArray()
        val k = key(); val decoded = SettingsCodec.decode(SettingsEncryption.decrypt(SettingsEncryption.encrypt(old, k), k))
        assertFalse(decoded.helperRegistryManaged); assertEquals(original.ui(), decoded.ui())
        assertEquals(original.helperToken, decoded.helperToken); assertEquals(original.secretHex, decoded.secretHex)
        assertFalse(SettingsCodec.decode(SettingsCodec.encode(decoded)).helperRegistryManaged)
        val invalidFlag = SettingsCodec.encode(decoded).also { it[it.lastIndex] = 2 }
        rejects { SettingsCodec.decode(invalidFlag) }
    }
}
