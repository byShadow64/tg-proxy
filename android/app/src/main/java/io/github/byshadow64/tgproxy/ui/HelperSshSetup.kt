package io.github.byshadow64.tgproxy.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import io.github.byshadow64.tgproxy.R

/** Password stays only in this unsaved composition and is cleared before dispatch. */
@Composable
internal fun HelperSshSetup(state: TgProxyUiState, initialIp: String, actions: TgProxyActions) {
    val ssh = state.sshSetup
    var ip by remember(initialIp) { mutableStateOf(initialIp) }
    var port by remember { mutableStateOf("22") }
    var user by remember { mutableStateOf("root") }
    var password by remember { mutableStateOf("") }
    var fingerprintChecked by remember(ssh.host, ssh.port, ssh.user, ssh.fingerprint) { mutableStateOf(false) }
    // This changes access to the server, so the owner must opt in explicitly.
    var registeredAccess by remember(ssh.host, ssh.port, ssh.user, ssh.fingerprint) { mutableStateOf(false) }
    var allowExistingUpgrade by remember(ssh.host, ssh.port, ssh.user, ssh.fingerprint) { mutableStateOf(false) }
    val busy = ssh.phase in setOf(SshSetupPhase.PROBING, SshSetupPhase.DEPLOYING, SshSetupPhase.VERIFYING)
    val endpointEditable = ssh.phase in setOf(SshSetupPhase.INPUT, SshSetupPhase.ERROR, SshSetupPhase.CANCELLED)
    val stopped = state.status in setOf(ProxyStatus.STOPPED, ProxyStatus.ERROR)
    LaunchedEffect(ssh.phase) { if (ssh.phase != SshSetupPhase.READY) password = "" }
    Column(Modifier.fillMaxWidth().testTag("ssh_setup"), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(stringResource(R.string.ssh_setup_title), style = MaterialTheme.typography.titleMedium)
        Text(stringResource(R.string.ssh_setup_body), style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(value = if (endpointEditable) ip else ssh.host,
            onValueChange = { ip = it.take(128) }, enabled = endpointEditable && !state.isSaving,
            label = { Text(stringResource(R.string.registry_ip)) }, singleLine = true,
            keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Uri),
            modifier = Modifier.fillMaxWidth().testTag("ssh_host"))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedTextField(value = if (endpointEditable) port else ssh.port.toString(), onValueChange = { port = it.take(5) },
                enabled = endpointEditable && !state.isSaving, label = { Text(stringResource(R.string.ssh_port)) }, singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), modifier = Modifier.weight(1f).testTag("ssh_port"))
            OutlinedTextField(value = if (endpointEditable) user else ssh.user, onValueChange = { user = it.take(32) },
                enabled = endpointEditable && !state.isSaving, label = { Text(stringResource(R.string.ssh_user)) }, singleLine = true,
                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Ascii), modifier = Modifier.weight(1f).testTag("ssh_user"))
        }
        if (endpointEditable) {
            Button(onClick = { actions.onProbeHelperSsh(ip.trim(), port, user.trim()) }, enabled = stopped && !state.isSaving,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("ssh_probe")) {
                Text(stringResource(R.string.ssh_probe_key))
            }
        }
        if (ssh.phase == SshSetupPhase.CONFIRM_HOST_KEY || ssh.phase == SshSetupPhase.READY) {
            Text(stringResource(R.string.ssh_key_verification), style = MaterialTheme.typography.bodySmall)
            Text(ssh.keyType + "\n" + ssh.fingerprint, fontFamily = FontFamily.Monospace,
                modifier = Modifier.testTag("ssh_fingerprint"), style = MaterialTheme.typography.bodySmall)
        }
        if (ssh.phase == SshSetupPhase.CONFIRM_HOST_KEY) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = fingerprintChecked, onCheckedChange = { fingerprintChecked = it }, modifier = Modifier.testTag("ssh_key_checked"))
                Text(stringResource(R.string.ssh_key_checked), Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
            }
            Button(onClick = actions.onConfirmHelperSshKey, enabled = fingerprintChecked && stopped,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("ssh_confirm_key")) {
                Text(stringResource(R.string.ssh_confirm_key))
            }
        }
        if (ssh.phase == SshSetupPhase.READY) {
            OutlinedTextField(value = password, onValueChange = { password = it.take(1024) },
                enabled = stopped && !state.isSaving, label = { Text(stringResource(R.string.ssh_password)) }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth().testTag("ssh_password"))
            Text(stringResource(R.string.ssh_password_memory), style = MaterialTheme.typography.bodySmall)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(registeredAccess, { registeredAccess = it }, modifier = Modifier.testTag("ssh_registered_access"))
                Text(stringResource(R.string.ssh_registered_access), Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(allowExistingUpgrade, { allowExistingUpgrade = it }, modifier = Modifier.testTag("ssh_allow_upgrade"))
                Text(stringResource(R.string.ssh_allow_upgrade), Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
            }
            Button(onClick = {
                val input = password.toCharArray(); password = ""
                actions.onDeployHelperSsh(input, registeredAccess, allowExistingUpgrade)
            }, enabled = stopped && !state.isSaving && password.isNotEmpty() && registeredAccess,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("ssh_deploy")) {
                Text(stringResource(R.string.ssh_install))
            }
        }
        if (busy) {
            val percent = ssh.percent
            if (percent == null) LinearProgressIndicator(Modifier.fillMaxWidth())
            else LinearProgressIndicator(progress = { percent.coerceIn(0, 100) / 100f }, modifier = Modifier.fillMaxWidth())
            TextButton(onClick = actions.onCancelHelperSsh, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("ssh_cancel")) {
                Text(stringResource(R.string.ui_cancel))
            }
        }
        ssh.progressMessage?.let { Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.testTag("ssh_progress")) }
        if (!busy && ssh.phase != SshSetupPhase.INPUT) {
            TextButton(onClick = { password = ""; actions.onResetHelperSsh() }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("ssh_reset")) {
                Text(stringResource(R.string.ssh_reset))
            }
        }
    }
}
