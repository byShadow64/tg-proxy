package io.github.byshadow64.tgproxy

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** The key is supplied by Android Keystore in production; never serialized. */
object SettingsEncryption {
    private val header = byteArrayOf(0x54, 0x47, 0x45, 1)
    private val aad = "TGProxy-Android-Settings-v1".toByteArray(Charsets.US_ASCII)
    fun encrypt(plaintext: ByteArray, key: SecretKey): ByteArray {
        require(plaintext.size <= 8192)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(aad)
        require(cipher.iv.size == 12)
        return header + cipher.iv + cipher.doFinal(plaintext)
    }
    fun decrypt(blob: ByteArray, key: SecretKey): ByteArray {
        require(blob.size in 32..8224 && blob.copyOfRange(0, 4).contentEquals(header))
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, blob.copyOfRange(4, 16)))
        cipher.updateAAD(aad)
        return cipher.doFinal(blob, 16, blob.size - 16)
    }
}
