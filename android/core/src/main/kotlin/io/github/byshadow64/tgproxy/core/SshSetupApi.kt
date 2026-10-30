package io.github.byshadow64.tgproxy.core

import java.security.MessageDigest
import java.util.Base64

class SshEndpoint(val ip: String, val port: Int = 22, val username: String = "root") {
    override fun toString() = "SshEndpoint(<private>)"
}

/** Immutable key preview bound to the exact endpoint the user confirmed. */
class SshHostKey internal constructor(val endpoint: SshEndpoint, val keyType: String, encoded: ByteArray) {
    internal val encoded = encoded.copyOf()
    val keyBase64: String = Base64.getEncoder().encodeToString(this.encoded)
    val sha256Fingerprint: String = "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(this.encoded))
    override fun toString() = "SshHostKey(<private>)"
}

class SshPayloadFile(val path: String, bytes: ByteArray, val sha256: String) {
    internal val bytes = bytes.copyOf()
    val size: Long get() = bytes.size.toLong()
    override fun toString() = "SshPayloadFile(path=$path, size=$size)"
}

class SshInstallOptions(
    val registryUrl: String,
    val registryTrustSpki: String,
    val publicIp: String,
    val allowRegisteredDevices: Boolean = false,
    val allowExistingPrivateUpgrade: Boolean = false,
) {
    override fun toString() = "SshInstallOptions(<private>)"
}

enum class SshInstallStage { CONNECTING, CHECKING_HOST_KEY, AUTHENTICATING, CHECKING_PRIVILEGES, UPLOADING, INSTALLING, VERIFYING_RESULT, COMPLETE }
data class SshInstallProgress(val stage: SshInstallStage, val sentBytes: Long = 0, val totalBytes: Long = 0)
enum class SshFailureCode { INVALID_REQUEST, INVALID_PAYLOAD, HOST_KEY_CHANGED, AUTHENTICATION_FAILED, ROOT_REQUIRED, CONNECTION_FAILED, UNSUPPORTED_SERVER, TIMEOUT, CANCELLED, INSTALL_FAILED, UNVERIFIED_RESULT }
class SshException(val code: SshFailureCode) : Exception(code.name)

/** Persist only after the separate signed registry lease confirms this IP, port and pin. */
class SshInstallResult(val host: String, val port: Int, val fingerprintHex: String, val helperId: String) {
    override fun toString() = "SshInstallResult(<private>)"
}

object SshHelperInstaller {
    fun preflight(endpoint: SshEndpoint, cancelled: () -> Boolean = { false }, progress: (SshInstallProgress) -> Unit = {}): SshHostKey =
        SshInstallerBackend.preflight(endpoint, cancelled, progress)

    /** Consumes and clears password on every outcome. No password, bearer token or remote stdout is logged. */
    fun deploy(endpoint: SshEndpoint, password: CharArray, accepted: SshHostKey, payload: List<SshPayloadFile>, options: SshInstallOptions,
        cancelled: () -> Boolean = { false }, progress: (SshInstallProgress) -> Unit = {}): SshInstallResult =
        SshInstallerBackend.deploy(endpoint, password, accepted, payload, options, cancelled, progress)
}
