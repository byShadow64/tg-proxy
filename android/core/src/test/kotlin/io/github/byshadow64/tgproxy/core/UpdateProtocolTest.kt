package io.github.byshadow64.tgproxy.core

import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.MessageDigest
import java.util.Base64

internal object UpdateFixture {
    val key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    val rawKey = key.public.encoded.takeLast(32).toByteArray()
    const val now = 1_793_260_000L
    fun payload(apk: ByteArray = "synthetic APK fixture".toByteArray()): Map<String, Any> {
        val hash = MessageDigest.getInstance("SHA-256").digest(apk).joinToString("") { "%02x".format(it.toInt() and 255) }
        return mapOf("v" to 1L, "package_name" to AndroidUpdateProtocol.PACKAGE_NAME, "channel" to "dev",
            "version_code" to 7L, "version_name" to "0.1.6-dev", "min_sdk" to 26L,
            "apk_path" to "/android-dev/releases/7/$hash.apk", "size" to apk.size.toLong(), "sha256" to hash,
            "signer_sha256" to AndroidUpdateProtocol.ORIGINAL_SIGNER_SHA256, "notes_ru" to "Обновление приложения",
            "notes_en" to "Application update", "published_at" to now)
    }
    fun signed(data: Map<String, Any> = payload(), domain: ByteArray = AndroidUpdateProtocol.DOMAIN): ByteArray = signedPayload(RegistryJson.canonical(data), domain)
    fun signedPayload(payload: ByteArray, domain: ByteArray = AndroidUpdateProtocol.DOMAIN): ByteArray {
        val signature = Signature.getInstance("Ed25519").run { initSign(key.private); update(domain + payload); sign() }
        return RegistryJson.canonical(mapOf("v" to 1L, "key_id" to AndroidUpdateProtocol.KEY_ID,
            "payload" to Base64.getEncoder().encodeToString(payload), "signature" to Base64.getEncoder().encodeToString(signature)))
    }
    fun verified(apk: ByteArray = "synthetic APK fixture".toByteArray()): AndroidUpdateManifest =
        AndroidUpdateProtocol.verifyWithKey(signed(payload(apk)), now, rawKey)
}

class UpdateProtocolTest {
    private fun reject(bytes: ByteArray, code: UpdateFailureCode = UpdateFailureCode.INVALID_METADATA) {
        try { AndroidUpdateProtocol.verifyWithKey(bytes, UpdateFixture.now, UpdateFixture.rawKey); fail("Untrusted update accepted") }
        catch (failure: UpdateException) { assertEquals(code, failure.code); assertEquals(code.name, failure.message); assertNull(failure.cause) }
    }

    @Test fun validSignedManifestIsReadOnlyAndRetainsCopyOfEnvelope() {
        val bytes = UpdateFixture.signed()
        val original = bytes.copyOf()
        val result = AndroidUpdateProtocol.verifyWithKey(bytes, UpdateFixture.now, UpdateFixture.rawKey)
        assertEquals(7L, result.versionCode); assertEquals("0.1.6-dev", result.versionName); assertEquals(26, result.minSdk)
        assertEquals("Обновление приложения", result.notesRu)
        bytes.fill(0); result.encoded().fill(0)
        assertArrayEquals(original, result.encoded())
    }

    @Test fun signaturesCannotCrossWindowsOrOtherDomains() {
        reject(UpdateFixture.signed(domain = "TGPROXY_STABLE_RELEASE_APPROVAL_V1\u0000".toByteArray()), UpdateFailureCode.SIGNATURE)
        val envelope = RegistryJson.parse(UpdateFixture.signed()).toMutableMap()
        val signature = Base64.getDecoder().decode(envelope["signature"] as String).apply { this[0] = (this[0].toInt() xor 1).toByte() }
        envelope["signature"] = Base64.getEncoder().encodeToString(signature)
        reject(RegistryJson.canonical(envelope), UpdateFailureCode.SIGNATURE)
    }

    @Test fun wrongPublisherKeyCannotAuthenticateManifest() {
        val wrong = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().public.encoded.takeLast(32).toByteArray()
        try { AndroidUpdateProtocol.verifyWithKey(UpdateFixture.signed(), UpdateFixture.now, wrong); fail() }
        catch (failure: UpdateException) { assertEquals(UpdateFailureCode.SIGNATURE, failure.code) }
        try { AndroidUpdateProtocol.verify(UpdateFixture.signed(), UpdateFixture.now); fail("Fixture signer trusted by production") }
        catch (failure: UpdateException) { assertEquals(UpdateFailureCode.SIGNATURE, failure.code) }
    }

    @Test fun signatureDoesNotPermitWrongPackageChannelOrApkSigner() {
        for ((key, value) in mapOf("package_name" to "other.app", "channel" to "stable", "signer_sha256" to "0".repeat(64))) {
            reject(UpdateFixture.signed(UpdateFixture.payload() + (key to value)))
        }
    }

    @Test fun apkLocationMustMatchExactVersionAndHashUnderFixedPrefix() {
        for (path in listOf("https://attacker.invalid/payload.apk", "//attacker.invalid/payload.apk", "/android-dev/../payload.apk", "/android-dev/releases/7/%2e%2e.apk", "/android-dev/releases/7/file.apk?x=1", "/android-dev/releases/8/${UpdateFixture.payload()["sha256"]}.apk")) {
            reject(UpdateFixture.signed(UpdateFixture.payload() + ("apk_path" to path)))
        }
    }

    @Test fun sizesVersionsAndSdkHaveStrictBoundsAndTypes() {
        for ((key, value) in listOf("size" to 0L, "size" to AndroidUpdateProtocol.MAX_APK_BYTES + 1,
            "size" to "20", "version_code" to 0L, "version_code" to Int.MAX_VALUE.toLong() + 1,
            "version_name" to "1.0.0", "version_name" to "0.1.6-dev\n", "min_sdk" to 25L, "min_sdk" to 101L,
            "sha256" to "G".repeat(64), "sha256" to "A".repeat(64))) {
            reject(UpdateFixture.signed(UpdateFixture.payload() + (key to value)))
        }
    }

    @Test fun futurePublicationIsBoundedButOldOfflineManifestDoesNotExpire() {
        reject(UpdateFixture.signed(UpdateFixture.payload() + ("published_at" to UpdateFixture.now + 86401)))
        val old = UpdateFixture.signed(UpdateFixture.payload() + ("published_at" to 1L))
        assertEquals(1L, AndroidUpdateProtocol.verifyWithKey(old, UpdateFixture.now, UpdateFixture.rawKey).publishedAt)
        assertNotNull(AndroidUpdateProtocol.verifyWithKey(UpdateFixture.signed(UpdateFixture.payload() + ("published_at" to UpdateFixture.now + 86400)), UpdateFixture.now, UpdateFixture.rawKey))
    }

    @Test fun signedPayloadMustBeCanonicalAndCannotHaveDuplicateOrUnknownFields() {
        val canonical = RegistryJson.canonical(UpdateFixture.payload()).toString(Charsets.US_ASCII)
        reject(UpdateFixture.signedPayload((" " + canonical).toByteArray()))
        reject(UpdateFixture.signedPayload(canonical.replaceFirst("{", "{\"v\":1,").toByteArray()))
        reject(UpdateFixture.signed(UpdateFixture.payload() + ("extra" to "ignored?")))
        reject(UpdateFixture.signed(UpdateFixture.payload() - "notes_en"))
    }

    @Test fun envelopeCannotSmuggleDuplicateKeysNonCanonicalBase64OrOversizeData() {
        val envelope = RegistryJson.parse(UpdateFixture.signed()).toMutableMap()
        reject((UpdateFixture.signed().toString(Charsets.US_ASCII).replaceFirst("{", "{\"v\":1,")).toByteArray())
        envelope["payload"] = (envelope["payload"] as String).trimEnd('=')
        // Make missing padding unambiguously noncanonical even when the normal payload had none.
        envelope["signature"] = (envelope["signature"] as String).trimEnd('=')
        reject(RegistryJson.canonical(envelope))
        reject(ByteArray(AndroidUpdateProtocol.MAX_METADATA_BYTES + 1) { 32 })
        reject(byteArrayOf(0xff.toByte(), 0xfe.toByte()))
    }

    @Test fun notesRejectControlCharactersUnpairedSurrogatesAndDirectionOverrides() {
        for (notes in listOf("line\nline", "\u0000", "\ud800", "safe\u202eevil", "x".repeat(1501), "")) {
            reject(UpdateFixture.signed(UpdateFixture.payload() + ("notes_ru" to notes)))
        }
    }
}
