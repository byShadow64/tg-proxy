package io.github.byshadow64.tgproxy.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import io.github.byshadow64.tgproxy.R
import io.github.byshadow64.tgproxy.UpdatePhase
import io.github.byshadow64.tgproxy.UpdateUiState
import java.util.Locale
import java.util.Date
import java.util.TimeZone

@Composable
internal fun UpdateCard(state: UpdateUiState, actions: TgProxyActions, settings: Boolean = false) {
    Card(Modifier.fillMaxWidth().testTag("update_card")) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(stringResource(R.string.update_title), style = MaterialTheme.typography.titleMedium)
            val text = when (state.phase) {
                UpdatePhase.IDLE -> stringResource(if (state.automatic) R.string.update_intro else R.string.update_intro_manual)
                UpdatePhase.CHECKING -> stringResource(R.string.update_checking)
                UpdatePhase.CURRENT -> stringResource(R.string.update_current)
                UpdatePhase.AVAILABLE -> stringResource(R.string.update_available, state.version)
                UpdatePhase.DOWNLOADING -> stringResource(R.string.update_downloading,
                    if (state.total > 0) (state.bytes * 100 / state.total).toInt().coerceIn(0, 100) else 0)
                UpdatePhase.VERIFYING -> stringResource(R.string.update_verifying)
                UpdatePhase.READY -> stringResource(R.string.update_ready)
                UpdatePhase.INSTALLING -> stringResource(R.string.update_installing)
                UpdatePhase.CONFIRM -> stringResource(R.string.update_confirm)
                UpdatePhase.ERROR -> stringResource(if (state.errorRes != 0) state.errorRes else R.string.update_network_error)
            }
            Text(text, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("update_status"))
            // A failed or cancelled Android installation retains the verified APK
            // and returns to READY so it can be retried. Keep its outcome visible
            // separately; READY describes the file, not installation success.
            if (state.errorRes != 0 && state.phase != UpdatePhase.ERROR) {
                Text(stringResource(state.errorRes), style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.testTag("update_error").semantics { liveRegion = LiveRegionMode.Polite })
            }
            if (state.phase == UpdatePhase.DOWNLOADING) {
                LinearProgressIndicator(progress = { if (state.total > 0) (state.bytes.toFloat() / state.total).coerceIn(0f, 1f) else 0f }, modifier = Modifier.fillMaxWidth())
                Text(stringResource(R.string.update_size, String.format(Locale.getDefault(), "%.1f", state.bytes / 1048576.0),
                    String.format(Locale.getDefault(), "%.1f", state.total / 1048576.0)), style = MaterialTheme.typography.bodySmall)
            } else if (state.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
            if (state.notes.isNotBlank() && state.phase in setOf(UpdatePhase.AVAILABLE, UpdatePhase.READY))
                Text(state.notes, style = MaterialTheme.typography.bodySmall)
            when (state.phase) {
                UpdatePhase.AVAILABLE -> Button(onClick = actions.onDownloadUpdate, modifier = Modifier.fillMaxWidth().testTag("update_download")) {
                    Text(stringResource(R.string.update_download))
                }
                UpdatePhase.READY, UpdatePhase.CONFIRM -> Button(onClick = actions.onInstallUpdate, modifier = Modifier.fillMaxWidth().testTag("update_install")) {
                    Text(stringResource(R.string.update_install))
                }
                UpdatePhase.CHECKING, UpdatePhase.DOWNLOADING, UpdatePhase.VERIFYING -> TextButton(onClick = actions.onCancelUpdate, modifier = Modifier.fillMaxWidth().testTag("update_cancel")) {
                    Text(stringResource(R.string.update_cancel))
                }
                UpdatePhase.INSTALLING -> Unit
                else -> OutlinedButton(onClick = actions.onCheckUpdate, modifier = Modifier.fillMaxWidth().testTag("update_check")) {
                    Text(stringResource(R.string.update_check))
                }
            }
            if (settings) {
                val context = LocalContext.current
                val locale = LocalConfiguration.current.locales[0]
                val is24Hour = android.text.format.DateFormat.is24HourFormat(context)
                val timezone = TimeZone.getDefault().id
                val checkedAt = remember(state.lastChecked, context, locale, is24Hour, timezone) {
                    if (state.lastChecked > 0) {
                        val date = Date(state.lastChecked)
                        android.text.format.DateFormat.getDateFormat(context).format(date) + " " +
                            android.text.format.DateFormat.getTimeFormat(context).format(date)
                    } else null
                }
                Text(if (checkedAt == null) stringResource(R.string.update_not_checked)
                    else stringResource(R.string.update_last_checked, checkedAt),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.testTag("update_last_checked"))
                Text(stringResource(R.string.update_install_note), style = MaterialTheme.typography.bodySmall)
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(stringResource(R.string.update_automatic), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                    Switch(state.automatic, { actions.onUpdateOptions(it, state.wifiDownload) }, modifier = Modifier.testTag("update_auto_check"))
                }
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(stringResource(R.string.update_wifi), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                    Switch(state.wifiDownload, { actions.onUpdateOptions(state.automatic, it) }, modifier = Modifier.testTag("update_auto_download"))
                }
                if (!state.busy && state.phase in setOf(UpdatePhase.AVAILABLE, UpdatePhase.READY)) TextButton(onClick = actions.onCheckUpdate,
                    modifier = Modifier.fillMaxWidth().testTag("update_check_again")) { Text(stringResource(R.string.update_check)) }
            }
        }
    }
}
