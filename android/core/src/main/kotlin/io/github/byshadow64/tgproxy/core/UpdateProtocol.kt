package io.github.byshadow64.tgproxy.core

import java.security.KeyFactory
import java.security.Provider
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

enum class UpdateFailureCode { INVALID_METADATA, SIGNATURE, NETWORK, TLS, HTTP, TIMEOUT, CANCELLED, SIZE, HASH, FILE }
class UpdateException(val code: UpdateFailureCode) : Exception(code.name)

/** Created only after signature/schema checks; APK identity is additionally checked by Android before install. */
class AndroidUpdateManifest internal constructor(
    val versionCode: Long,
    val versionName: String,
    val minSdk: Int,
    val apkPath: String,
    val size: Long,
    val sha256: String,
    val signerSha256: String,
    val notesRu: String,
    val notesEn: String,
    val publishedAt: Long,
    envelope: ByteArray,
) {
    private val envelope = envelope.copyOf()
    fun encoded(): ByteArray = envelope.copyOf()
}

/** A separate signature domain prevents a Windows release/approval from becoming an Android update. */
object AndroidUpdateProtocol {
    const val PACKAGE_NAME = "io.github.byshadow64.tgproxy"
    const val CHANNEL = "dev"
    const val KEY_ID = "tgproxy-2026-01"
    const val ORIGINAL_SIGNER_SHA256 = "266924f2558b9a81571376f37d21c59310028d810fd6f1e0b2c4e064a0fc71c0"
    const val MAX_METADATA_BYTES = 16 * 1024
    const val MAX_APK_BYTES = 64L * 1024 * 1024
    internal val DOMAIN = "TGPROXY_ANDROID_UPDATE_V1\u0000".toByteArray(Charsets.US_ASCII)
    private const val TRUSTED_KEY = "/JUuGMEQXZSPxtFaxPZO0W6js51c+ocOXq1WL9Qe1z8="
    private val fields = setOf("v", "package_name", "channel", "version_code", "version_name", "min_sdk", "apk_path", "size", "sha256", "signer_sha256", "notes_ru", "notes_en", "published_at")

    fun verify(bytes: ByteArray, nowSeconds: Long = System.currentTimeMillis() / 1000): AndroidUpdateManifest =
        verifyWithKey(bytes, nowSeconds, Base64.getDecoder().decode(TRUSTED_KEY))

    /** Internal key injection belongs to tests; the shipped application has one compiled trust anchor. */
    internal fun verifyWithKey(bytes: ByteArray, nowSeconds: Long, rawKey: ByteArray): AndroidUpdateManifest {
        try {
            require(bytes.size in 1..MAX_METADATA_BYTES && nowSeconds > 0)
            val outer = RegistryJson.parse(bytes)
            require(outer.keys == setOf("v", "key_id", "payload", "signature"))
            require(outer["v"] == 1L && outer["key_id"] == KEY_ID)
            val payload = decode(outer["payload"], MAX_METADATA_BYTES)
            val signature = decode(outer["signature"], 64)
            require(signature.size == 64 && rawKey.size == 32)
            if (!verifySignature(rawKey, DOMAIN + payload, signature)) throw UpdateException(UpdateFailureCode.SIGNATURE)
            val data = RegistryJson.parse(payload)
            require(data.keys == fields && RegistryJson.canonical(data).contentEquals(payload))
            require(data["v"] == 1L && data["package_name"] == PACKAGE_NAME && data["channel"] == CHANNEL)
            val version = number(data, "version_code", 1L..Int.MAX_VALUE.toLong())
            val name = string(data, "version_name", 40)
            require(name.matches(Regex("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}-dev(?:\\.[0-9]{1,3})?")))
            val minSdk = number(data, "min_sdk", 26L..100L).toInt()
            val size = number(data, "size", 1L..MAX_APK_BYTES)
            val hash = string(data, "sha256", 64).also { require(it.matches(Regex("[0-9a-f]{64}"))) }
            val signer = string(data, "signer_sha256", 64).also { require(it == ORIGINAL_SIGNER_SHA256) }
            val path = string(data, "apk_path", 140)
            require(path == "/android-dev/releases/$version/$hash.apk")
            val published = number(data, "published_at", 1L..Long.MAX_VALUE)
            require(published <= nowSeconds || published - nowSeconds <= 24 * 60 * 60)
            return AndroidUpdateManifest(version, name, minSdk, path, size, hash, signer,
                string(data, "notes_ru", 1500), string(data, "notes_en", 1500), published, bytes)
        } catch (failure: UpdateException) { throw failure }
        catch (_: Exception) { throw UpdateException(UpdateFailureCode.INVALID_METADATA) }
    }

    private fun decode(value: Any?, max: Int): ByteArray {
        require(value is String && value.length <= ((max + 2) / 3) * 4)
        val bytes = Base64.getDecoder().decode(value)
        require(bytes.size <= max && Base64.getEncoder().encodeToString(bytes) == value)
        return bytes
    }
    private fun number(data: Map<String, Any>, key: String, range: LongRange): Long =
        (data[key] as? Long).also { require(it != null && it in range) }!!
    private fun string(data: Map<String, Any>, key: String, max: Int): String {
        val value = data[key] as? String ?: error("invalid string")
        require(value.length in 1..max && value.none { Character.isISOControl(it) || Character.isSurrogate(it) || it in '\u202a'..'\u202e' || it in '\u2066'..'\u2069' })
        return value
    }
    private fun verifySignature(rawKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        try {
            // API26 does not provide Ed25519. The already pinned bcprov runtime is used
            // explicitly, never installed as a global provider or used to replace TLS trust.
            val provider = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider")
                .getDeclaredConstructor().newInstance() as Provider
            val prefix = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
            val key = KeyFactory.getInstance("Ed25519", provider).generatePublic(X509EncodedKeySpec(prefix + rawKey))
            return Signature.getInstance("Ed25519", provider).run { initVerify(key); update(message); verify(signature) }
        } catch (_: Exception) { throw UpdateException(UpdateFailureCode.SIGNATURE) }
    }
}
