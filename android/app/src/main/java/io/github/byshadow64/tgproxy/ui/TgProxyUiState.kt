package io.github.byshadow64.tgproxy.ui

/** A memory-only editor snapshot. Never log it or place it in saved instance state. */
class ProxySettingsUi(
    val localPort: String = "1443",
    val helperEnabled: Boolean = false,
    val helperHost: String = "",
    val helperPort: String = "8444",
    val helperCertificateSha256: String = "",
    val helperToken: String = "",
    val helperRegistryManaged: Boolean = false,
) {
    fun copy(
        localPort: String = this.localPort,
        helperEnabled: Boolean = this.helperEnabled,
        helperHost: String = this.helperHost,
        helperPort: String = this.helperPort,
        helperCertificateSha256: String = this.helperCertificateSha256,
        helperToken: String = this.helperToken,
        helperRegistryManaged: Boolean = this.helperRegistryManaged,
    ) = ProxySettingsUi(localPort, helperEnabled, helperHost, helperPort, helperCertificateSha256, helperToken, helperRegistryManaged)

    override fun toString() = "ProxySettingsUi(<private>)"

    override fun equals(other: Any?): Boolean = other is ProxySettingsUi &&
        localPort == other.localPort && helperEnabled == other.helperEnabled &&
        helperHost == other.helperHost && helperPort == other.helperPort &&
        helperCertificateSha256 == other.helperCertificateSha256 && helperToken == other.helperToken && helperRegistryManaged == other.helperRegistryManaged

    override fun hashCode(): Int {
        var result = localPort.hashCode()
        result = 31 * result + helperEnabled.hashCode()
        result = 31 * result + helperHost.hashCode()
        result = 31 * result + helperPort.hashCode()
        result = 31 * result + helperCertificateSha256.hashCode()
        result = 31 * result + helperToken.hashCode()
        return 31 * result + helperRegistryManaged.hashCode()
    }
}

enum class ProxyStatus { STOPPED, STARTING, RUNNING, STOPPING, ERROR }
enum class LogLevel { INFO, WARNING, ERROR }
enum class PairingStatus { IDLE, CONNECTING, SUCCESS, ERROR }
enum class SshSetupPhase { INPUT, PROBING, CONFIRM_HOST_KEY, READY, DEPLOYING, VERIFYING, SUCCESS, ERROR, CANCELLED }

data class SshSetupUiState(
    val phase: SshSetupPhase = SshSetupPhase.INPUT,
    val host: String = "", val port: Int = 22, val user: String = "root",
    val keyType: String = "", val fingerprint: String = "",
    val progressMessage: String? = null, val percent: Int? = null,
) { override fun toString() = "SshSetupUiState(phase=$phase, <private>)" }

data class UiMetrics(
    val activeConnections: Int = 0,
    val bytesReceived: Long = 0,
    val bytesSent: Long = 0,
    val directConnections: Long = 0,
    val helperConnections: Long = 0,
)

/** Message and timestamp must be safe, localized display text from structured events. */
data class JournalEntry(
    val id: Long,
    val timestamp: String,
    val level: LogLevel,
    val message: String,
)

/** Short-lived action feedback, separate from the persistent proxy failure. */
data class UiFeedback(val id: Long, val message: String)

object SettingsFields {
    const val LOCAL_PORT = "localPort"
    const val HELPER_HOST = "helperHost"
    const val HELPER_PORT = "helperPort"
    const val HELPER_CERTIFICATE_SHA256 = "helperCertificateSha256"
    const val HELPER_TOKEN = "helperToken"
}

object PairingFields {
    const val HOST = "pairHost"
    const val CODE = "pairCode"
}

data class TgProxyUiState(
    val settings: ProxySettingsUi = ProxySettingsUi(),
    val status: ProxyStatus = ProxyStatus.STOPPED,
    val runningPort: Int? = null,
    val metrics: UiMetrics = UiMetrics(),
    val journal: List<JournalEntry> = emptyList(),
    val validationErrors: Map<String, String> = emptyMap(),
    val statusMessage: String? = null,
    val feedback: UiFeedback? = null,
    val connection: io.github.byshadow64.tgproxy.ConnectionAvailability = io.github.byshadow64.tgproxy.ConnectionAvailability.UNKNOWN,
    val hasSavedSettings: Boolean = false,
    val isSaving: Boolean = false,
    val pairingStatus: PairingStatus = PairingStatus.IDLE,
    val pairingMessage: String? = null,
    val pairingValidationErrors: Map<String, String> = emptyMap(),
    val registrySetupRequired: Boolean = false,
    val sshSetup: SshSetupUiState = SshSetupUiState(),
    val incomingHelperLink: HelperIpLink? = null,
    val update: io.github.byshadow64.tgproxy.UpdateUiState = io.github.byshadow64.tgproxy.UpdateUiState(),
)

data class TgProxyActions(
    val onFeedbackConsumed: (Long) -> Unit = {},
    val onCheckUpdate: () -> Unit = {},
    val onDownloadUpdate: () -> Unit = {},
    val onInstallUpdate: () -> Unit = {},
    val onCancelUpdate: () -> Unit = {},
    val onUpdateOptions: (Boolean, Boolean) -> Unit = { _, _ -> },
    val onStart: () -> Unit = {},
    val onReconnect: () -> Unit = {},
    val onStop: () -> Unit = {},
    val onOpenTelegram: () -> Unit = {},
    val onCopyTelegramLink: () -> Unit = {},
    val onSaveSettings: (ProxySettingsUi) -> Unit = {},
    val onRestartWithSettings: (ProxySettingsUi) -> Unit = {},
    val onClearJournal: () -> Unit = {},
    val onCopyJournal: () -> Unit = {},
    val onConnectHelperIp: (host: String) -> Unit = {},
    val onCancelHelperConnect: () -> Unit = {},
    val onProbeHelperSsh: (host: String, port: String, user: String) -> Unit = { _, _, _ -> },
    val onConfirmHelperSshKey: () -> Unit = {},
    val onDeployHelperSsh: (password: CharArray, allowRegisteredDevices: Boolean, allowExistingUpgrade: Boolean) -> Unit = { password, _, _ -> password.fill('\u0000') },
    val onCancelHelperSsh: () -> Unit = {},
    val onResetHelperSsh: () -> Unit = {},
    val onOpenImportedTelegramProxy: (TelegramProxyLink) -> Unit = {},
    val onOpenNotificationSettings: () -> Unit = {},
    val onOpenBatterySettings: () -> Unit = {},
    val onCopyHelperLink: (HelperIpLink) -> Unit = {},
    val onConsumeIncomingHelperLink: () -> Unit = {},
)
