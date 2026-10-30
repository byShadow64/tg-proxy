package io.github.byshadow64.tgproxy

import io.github.byshadow64.tgproxy.core.EngineConfig
import io.github.byshadow64.tgproxy.core.HelperSettings
import io.github.byshadow64.tgproxy.ui.ProxySettingsUi
import io.github.byshadow64.tgproxy.ui.SettingsFields
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.IDN
import java.net.URI
import java.security.SecureRandom
import java.util.Locale

class AppSettings(
    val port: Int = 1443,
    val secretHex: String,
    val helperEnabled: Boolean = false,
    val helperHost: String = "",
    val helperPort: Int = 8444,
    val helperFingerprint: String = "",
    val helperToken: String = "",
    val helperRegistryManaged: Boolean = false,
) {
    override fun toString() = "AppSettings(<private>)"
    fun ui() = ProxySettingsUi(port.toString(), helperEnabled, helperHost, helperPort.toString(), helperFingerprint, helperToken, helperRegistryManaged)
    fun engine() = EngineConfig(port, secretHex, if (helperEnabled) HelperSettings(helperHost, helperPort, helperFingerprint, helperToken) else null)
    companion object {
        fun fresh(): AppSettings {
            val bytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
            return AppSettings(secretHex = bytes.joinToString("") { "%02x".format(it.toInt() and 255) })
        }
    }
}

data class ValidationResult(val settings: AppSettings?, val errors: Map<String, String>)

object SettingsValidation {
    private fun validHost(host: String): Boolean {
        if (host.isEmpty() || host.length > 253 || host.any { it.isWhitespace() || it.code < 32 } || host.any { it in "/\\@?#%[]" }) return false
        if (':' in host) return try { URI("https://[$host]").host != null } catch (_: Exception) { false }
        return try {
            val ascii = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES)
            ascii.split('.').all { it.isNotEmpty() && it.length <= 63 && !it.startsWith('-') && !it.endsWith('-') }
        } catch (_: IllegalArgumentException) { false }
    }
    fun parse(ui: ProxySettingsUi, previous: AppSettings): ValidationResult {
        val errors = linkedMapOf<String, String>()
        val port = ui.localPort.toIntOrNull()
        if (port == null || port !in 1024..65535) errors[SettingsFields.LOCAL_PORT] = "port"
        val host = ui.helperHost.trim()
        val hp = ui.helperPort.toIntOrNull()
        val pin = ui.helperCertificateSha256.replace(":", "").replace(" ", "").lowercase(Locale.ROOT)
        val validAddress = if (ui.helperRegistryManaged) try { io.github.byshadow64.tgproxy.core.HelperRegistryClient.numericIp(host) == host } catch (_: Exception) { false } else validHost(host)
        if (host.length > 253 || (ui.helperEnabled && !validAddress)) errors[SettingsFields.HELPER_HOST] = "host"
        if (ui.helperEnabled && (hp == null || hp !in 1..65535)) errors[SettingsFields.HELPER_PORT] = "port"
        if (pin.length > 128 || (ui.helperEnabled && !pin.matches(Regex("[0-9a-f]{64}")))) errors[SettingsFields.HELPER_CERTIFICATE_SHA256] = "pin"
        val tokenBytes = ui.helperToken.toByteArray(Charsets.UTF_8).size
        if (ui.helperRegistryManaged) {
            // A short-lived registry bearer lease belongs only in process memory, never in saved settings.
            if (ui.helperToken.isNotEmpty()) errors[SettingsFields.HELPER_TOKEN] = "token"
        } else if (tokenBytes > 512 || ui.helperToken.any { it.code < 32 || it.code == 127 } || (ui.helperEnabled && tokenBytes < 32)) errors[SettingsFields.HELPER_TOKEN] = "token"
        if (errors.isNotEmpty()) return ValidationResult(null, errors)
        return ValidationResult(AppSettings(port!!, previous.secretHex, ui.helperEnabled, host, hp?.takeIf { it in 1..65535 } ?: previous.helperPort, pin, ui.helperToken, ui.helperRegistryManaged), emptyMap())
    }
    fun isValid(settings: AppSettings): Boolean = settings.secretHex.matches(Regex("[0-9a-f]{32}")) && parse(settings.ui(), settings).settings != null
}

/** Versioned bounded binary payload; the entire payload is encrypted before persistence. */
object SettingsCodec {
    private const val MAGIC_V1 = 0x54475031
    private const val MAGIC = 0x54475032
    fun encode(s: AppSettings): ByteArray {
        require(SettingsValidation.isValid(s))
        return ByteArrayOutputStream().also { bytes ->
            DataOutputStream(bytes).use { out ->
                out.writeInt(MAGIC); out.writeInt(s.port); out.writeUTF(s.secretHex)
                out.writeBoolean(s.helperEnabled); out.writeUTF(s.helperHost); out.writeInt(s.helperPort)
                out.writeUTF(s.helperFingerprint); out.writeUTF(s.helperToken)
                out.writeBoolean(s.helperRegistryManaged)
            }
        }.toByteArray()
    }
    fun decode(bytes: ByteArray): AppSettings {
        require(bytes.size in 16..8192)
        return DataInputStream(ByteArrayInputStream(bytes)).use { input ->
            val magic = input.readInt(); require(magic == MAGIC || magic == MAGIC_V1)
            val port = input.readInt(); val secret = input.readUTF(); val enabled = input.readBoolean()
            val host = input.readUTF(); val helperPort = input.readInt(); val pin = input.readUTF(); val token = input.readUTF()
            val managed = if (magic == MAGIC) input.readUnsignedByte().also { require(it in 0..1) } == 1 else false
            val s = AppSettings(port, secret, enabled, host, helperPort, pin, token, managed)
            require(input.available() == 0 && SettingsValidation.isValid(s))
            s
        }
    }
}
