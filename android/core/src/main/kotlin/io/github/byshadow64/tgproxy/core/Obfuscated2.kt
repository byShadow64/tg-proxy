package io.github.byshadow64.tgproxy.core

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal enum class TransportProtocol(val tag: Int) { ABRIDGED(0xef), INTERMEDIATE(0xee), PADDED_INTERMEDIATE(0xdd) }
internal data class ClientHandshake(val dc: Int, val media: Boolean, val protocol: TransportProtocol, val prekeyIv: ByteArray)
internal data class HandshakeInspection(val handshake: ClientHandshake? = null, val failure: HandshakeFailure? = null)
internal class StreamCipher(key: ByteArray, iv: ByteArray) {
    private val cipher = Cipher.getInstance("AES/CTR/NoPadding").apply {
        init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
    }
    fun update(bytes: ByteArray): ByteArray = if (bytes.isEmpty()) bytes else cipher.update(bytes)
    fun skipInit() { update(ByteArray(64)) }
}

internal class CryptoContext(
    val clientDecrypt: StreamCipher, val clientEncrypt: StreamCipher,
    val telegramEncrypt: StreamCipher, val telegramDecrypt: StreamCipher,
)

internal object Obfuscated2 {
    private val random = SecureRandom()
    private val forbidden = listOf("HEAD", "POST", "GET ", "OPTI").map { it.toByteArray(Charsets.US_ASCII) } +
        listOf(byteArrayOf(-18, -18, -18, -18), byteArrayOf(-35, -35, -35, -35), byteArrayOf(0x16, 0x03, 0x01, 0x02))

    fun secret(hex: String): ByteArray {
        require(hex.length == 32 && hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' })
        return ByteArray(16) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    fun parse(init: ByteArray, secret: ByteArray): ClientHandshake? = inspect(init, secret).handshake

    fun inspect(init: ByteArray, secret: ByteArray): HandshakeInspection {
        if (init.size != 64 || secret.size != 16) return HandshakeInspection(failure = HandshakeFailure.INVALID_LENGTH)
        val prekeyIv = init.copyOfRange(8, 56)
        val plain = StreamCipher(hash(prekeyIv.copyOfRange(0, 32) + secret), prekeyIv.copyOfRange(32, 48)).update(init)
        val protocol = TransportProtocol.entries.firstOrNull { p -> (56..59).all { plain[it].toInt() and 255 == p.tag } }
            ?: return HandshakeInspection(failure = HandshakeFailure.SECRET_OR_PROTOCOL)
        val signed = ((plain[60].toInt() and 255) or (plain[61].toInt() shl 8)).toShort().toInt()
        if (signed == 0) return HandshakeInspection(failure = HandshakeFailure.ZERO_DC)
        if (signed == Short.MIN_VALUE.toInt()) return HandshakeInspection(failure = HandshakeFailure.RESERVED_DC)
        return HandshakeInspection(ClientHandshake(kotlin.math.abs(signed), signed < 0, protocol, prekeyIv))
    }

    fun relayInit(handshake: ClientHandshake, entropy: (Int) -> ByteArray = { ByteArray(it).also(random::nextBytes) }): ByteArray {
        val init: ByteArray
        while (true) {
            val candidate = entropy(64)
            require(candidate.size == 64)
            if ((candidate[0].toInt() and 255) == 0xef || forbidden.any { candidate.copyOfRange(0, 4).contentEquals(it) } ||
                (4..7).all { candidate[it] == 0.toByte() }) continue
            init = candidate.copyOf()
            break
        }
        val key = init.copyOfRange(8, 40)
        val iv = init.copyOfRange(40, 56)
        val encrypted = StreamCipher(key, iv).update(init)
        val dc = if (handshake.media) -handshake.dc else handshake.dc
        val tail = ByteArray(8)
        for (i in 0..3) tail[i] = handshake.protocol.tag.toByte()
        tail[4] = dc.toByte(); tail[5] = (dc shr 8).toByte()
        val padding = entropy(2)
        require(padding.size == 2)
        tail[6] = padding[0]; tail[7] = padding[1]
        for (i in 0..7) init[56 + i] = (tail[i].toInt() xor encrypted[56 + i].toInt() xor init[56 + i].toInt()).toByte()
        return init
    }

    fun context(handshake: ClientHandshake, secret: ByteArray, relayInit: ByteArray): CryptoContext {
        val client = handshake.prekeyIv
        val reverseClient = client.reversedArray()
        val reverseRelay = relayInit.copyOfRange(8, 56).reversedArray()
        return CryptoContext(
            StreamCipher(hash(client.copyOfRange(0, 32) + secret), client.copyOfRange(32, 48)).also { it.skipInit() },
            StreamCipher(hash(reverseClient.copyOfRange(0, 32) + secret), reverseClient.copyOfRange(32, 48)),
            StreamCipher(relayInit.copyOfRange(8, 40), relayInit.copyOfRange(40, 56)).also { it.skipInit() },
            StreamCipher(reverseRelay.copyOfRange(0, 32), reverseRelay.copyOfRange(32, 48)),
        )
    }

    private fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
}
