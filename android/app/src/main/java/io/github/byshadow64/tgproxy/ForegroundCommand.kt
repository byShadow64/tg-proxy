package io.github.byshadow64.tgproxy

import androidx.lifecycle.ViewModel

/** Public endpoint/action data only. Never retain an Activity, password or credential closure. */
internal sealed interface ForegroundCommand {
    data class Start(val action: String) : ForegroundCommand
    data class ConnectHelper(val host: String) : ForegroundCommand
    data class ProbeSsh(val host: String, val port: String, val user: String) : ForegroundCommand
}

/** RAM-only across configuration changes; deliberately excluded from saved state/process recovery. */
internal class ForegroundCommandViewModel : ViewModel() {
    val pending = PendingForegroundCommand()
}

internal class PendingForegroundCommand {
    private var command: ForegroundCommand? = null
    private var permissionReturned = false

    fun request(value: ForegroundCommand): Boolean {
        if (command != null) return false
        command = value
        permissionReturned = false
        return true
    }

    fun permissionReturned() { permissionReturned = true }

    fun take(started: Boolean): ForegroundCommand? {
        if (!started || !permissionReturned) return null
        return command.also { command = null; permissionReturned = false }
    }
}
