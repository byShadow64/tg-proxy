package io.github.byshadow64.tgproxy.ui

import android.graphics.BitmapFactory
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.byshadow64.tgproxy.R
import io.github.byshadow64.tgproxy.BuildConfig
import io.github.byshadow64.tgproxy.ui.theme.TgProxyTheme
import java.text.NumberFormat

/** Native, system-themed UI. All service effects are dispatched through explicit actions. */
@Composable
fun TgProxyApp(state: TgProxyUiState, actions: TgProxyActions, updatesRequest: Int = 0) {
    TgProxyTheme {
        var selectedTab by rememberSaveable { mutableIntStateOf(0) }
        LaunchedEffect(updatesRequest) { if (updatesRequest > 0) selectedTab = 3 }
        // The draft contains a token: it must stay out of rememberSaveable and Bundle state.
        var draft by remember { mutableStateOf(state.settings.copy()) }
        var draftBase by remember { mutableStateOf(state.settings.copy()) }
        LaunchedEffect(state.settings) {
            val saved = state.settings
            // A verified Helper may update in the background while the user edits
            // the local port. Preserve that edit, but always take new server secrets
            // from the verified profile; never restore stale hidden credentials.
            draft = saved.copy(
                localPort = if (draft.localPort != draftBase.localPort) draft.localPort else saved.localPort,
                helperEnabled = if (saved.helperHost == draftBase.helperHost && draft.helperEnabled != draftBase.helperEnabled)
                    draft.helperEnabled else saved.helperEnabled,
            )
            draftBase = saved.copy()
        }
        var helperIp by remember(state.settings.helperHost, state.settings.helperRegistryManaged) {
            mutableStateOf(if (state.settings.helperRegistryManaged) state.settings.helperHost else "")
        }
        var showLinkImport by remember { mutableStateOf(false) }
        var incomingPreview by remember { mutableStateOf<HelperIpLink?>(null) }
        val openLinkImport = { incomingPreview = null; showLinkImport = true }
        LaunchedEffect(state.incomingHelperLink) {
            state.incomingHelperLink?.let {
                incomingPreview = it
                showLinkImport = true
                actions.onConsumeIncomingHelperLink()
            }
        }
        val labels = listOf(R.string.ui_overview, R.string.nav_routes, R.string.ui_journal, R.string.help_tab)
        val icons = listOf(AppIcon.OVERVIEW, AppIcon.ROUTES, AppIcon.JOURNAL, AppIcon.HELP)
        if (showLinkImport) {
            LinkImportDialog(state, actions, incomingPreview,
                onDismiss = { showLinkImport = false; incomingPreview = null },
                onHelperConfirmed = { selectedTab = 1 },
            )
        }

        Scaffold(
            modifier = Modifier.fillMaxSize().testTag("app_root"),
            containerColor = MaterialTheme.colorScheme.background,
            topBar = { AppHeader() },
            bottomBar = {
                NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
                    labels.forEachIndexed { index, label ->
                        NavigationBarItem(
                            modifier = Modifier.testTag("nav_$index"),
                            selected = selectedTab == index,
                            onClick = { selectedTab = index },
                            icon = { Glyph(icons[index]) },
                            label = { Text(stringResource(label), style = MaterialTheme.typography.labelSmall, maxLines = 1) },
                            alwaysShowLabel = true,
                        )
                    }
                }
            },
        ) { padding ->
            when (selectedTab) {
                0 -> Overview(state, actions, Modifier.padding(padding))
                1 -> Routes(
                    state = state,
                    draft = draft,
                    onDraftChange = { draft = it },
                    helperIp = helperIp,
                    onHelperIpChange = { helperIp = it },
                    actions = actions,
                    onImportLink = openLinkImport,
                    modifier = Modifier.padding(padding),
                )
                2 -> Journal(state, actions, Modifier.padding(padding))
                else -> Help(state.update, actions, openLinkImport, { selectedTab = it }, Modifier.padding(padding))
            }
        }
    }
}

@Composable
private fun LinkImportDialog(
    state: TgProxyUiState,
    actions: TgProxyActions,
    initial: HelperIpLink?,
    onDismiss: () -> Unit,
    onHelperConfirmed: () -> Unit,
) {
    // A pasted Telegram link contains a secret. No saved state or automatic clipboard access.
    var input by remember(initial) { mutableStateOf(initial?.uri.orEmpty()) }
    var parsed by remember(initial) { mutableStateOf<ParsedProxyLink?>(initial) }
    var invalid by remember(initial) { mutableStateOf(false) }
    val preview = parsed
    val busy = state.isSaving || state.pairingStatus == PairingStatus.CONNECTING ||
        state.status in setOf(ProxyStatus.STARTING, ProxyStatus.STOPPING) ||
        state.sshSetup.phase in setOf(SshSetupPhase.PROBING, SshSetupPhase.CONFIRM_HOST_KEY,
            SshSetupPhase.READY, SshSetupPhase.DEPLOYING, SshSetupPhase.VERIFYING)
    val enabled = !busy && when (preview) {
        is HelperIpLink -> state.status == ProxyStatus.STOPPED || state.status == ProxyStatus.ERROR
        is TelegramProxyLink -> !preview.isLoopback || state.status == ProxyStatus.RUNNING
        null -> false
    }
    fun dismiss() { input = ""; parsed = null; onDismiss() }
    AlertDialog(
        modifier = Modifier.widthIn(max = (LocalConfiguration.current.screenWidthDp - 32).coerceAtLeast(280).dp).testTag("link_dialog"),
        onDismissRequest = { dismiss() },
        title = { Text(stringResource(R.string.link_title)) },
        text = {
            Column(Modifier.fillMaxWidth().heightIn(max = 380.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = input,
                    onValueChange = { input = it.take(ProxyLinkParser.MAX_LINK_LENGTH + 1); parsed = null; invalid = false },
                    label = { Text(stringResource(R.string.link_input)) },
                    keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Password),
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth().testTag("field_import_link"),
                    maxLines = 3,
                    isError = invalid,
                )
                BodyText(stringResource(R.string.link_formats))
                OutlinedButton(
                    onClick = {
                        parsed = runCatching { ProxyLinkParser.parse(input) }.getOrNull()
                        invalid = parsed == null
                    },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("preview_import_link"),
                    enabled = input.isNotBlank(),
                ) { Text(stringResource(R.string.link_preview_button)) }
                if (invalid) Notice(stringResource(R.string.link_invalid), error = true)
                when (preview) {
                    is HelperIpLink -> {
                        Text(stringResource(R.string.link_helper_title), fontWeight = FontWeight.SemiBold)
                        Text(preview.ip, fontFamily = FontFamily.Monospace, modifier = Modifier.testTag("link_preview_host"))
                        BodyText(stringResource(R.string.link_helper_body))
                        if (!enabled) BodyText(stringResource(R.string.link_helper_stopped))
                    }
                    is TelegramProxyLink -> {
                        Text(stringResource(if (preview.isLoopback) R.string.link_local_title else R.string.link_remote_title),
                            fontWeight = FontWeight.SemiBold)
                        Text(stringResource(R.string.link_endpoint, preview.host, preview.port),
                            modifier = Modifier.testTag("link_preview_host"))
                        Text(stringResource(R.string.link_secret_masked), modifier = Modifier.testTag("link_preview_mask"))
                        BodyText(stringResource(if (preview.isLoopback) R.string.link_local_body else R.string.link_remote_body))
                        if (preview.isLoopback && state.status != ProxyStatus.RUNNING) BodyText(stringResource(R.string.link_local_stopped))
                    }
                    null -> Unit
                }
                BodyText(stringResource(R.string.link_format_only))
            }
        },
        confirmButton = {
            if (preview != null) {
                TextButton(enabled = enabled, modifier = Modifier.heightIn(min = 48.dp).testTag("confirm_import_link"),
                    onClick = {
                        dismiss()
                        when (preview) {
                            is HelperIpLink -> { onHelperConfirmed(); actions.onConnectHelperIp(preview.ip) }
                            is TelegramProxyLink -> if (preview.isLoopback) actions.onOpenTelegram() else actions.onOpenImportedTelegramProxy(preview)
                        }
                    }) {
                    Text(stringResource(when (preview) {
                        is HelperIpLink -> R.string.link_helper_confirm
                        is TelegramProxyLink -> if (preview.isLoopback) R.string.link_local_confirm else R.string.ui_open_telegram
                    }))
                }
            }
        },
        dismissButton = {
            TextButton(onClick = { dismiss() }, modifier = Modifier.heightIn(min = 48.dp).testTag("dismiss_import_link")) {
                Text(stringResource(R.string.ui_cancel))
            }
        },
    )
}

@Composable
private fun Help(
    update: io.github.byshadow64.tgproxy.UpdateUiState,
    actions: TgProxyActions,
    onImportLink: () -> Unit,
    onNavigate: (Int) -> Unit,
    modifier: Modifier,
) {
    var showConnectionHelp by rememberSaveable { mutableStateOf(false) }
    var showBackgroundHelp by rememberSaveable { mutableStateOf(false) }
    var showHelperHelp by rememberSaveable { mutableStateOf(false) }
    var showDevices by rememberSaveable { mutableStateOf(false) }
    LazyColumn(modifier.fillMaxSize().testTag("help_content"),
        contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 8.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)) {
        item(key = "help_title") { ScreenTitle(stringResource(R.string.help_tab), stringResource(R.string.help_subtitle)) }
        item(key = "help_quick_start") {
            AppCard {
                CardHeading(AppIcon.TELEGRAM, stringResource(R.string.help_start_title))
                BodyText(stringResource(R.string.help_intro_body))
                Spacer(Modifier.height(12.dp))
                BodyText(stringResource(R.string.help_start_body), Modifier.testTag("help_start_steps"))
                Spacer(Modifier.height(12.dp))
                BodyText(stringResource(R.string.help_local_body))
                Spacer(Modifier.height(12.dp))
                BodyText(stringResource(R.string.help_stop_body))
                TextButton(onClick = { onNavigate(0) }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("help_overview")) {
                    Text(stringResource(R.string.help_overview_button))
                }
            }
        }
        item(key = "help_updates") { UpdateCard(update, actions, settings = true) }
        item(key = "help_connection") {
            HelpTopic(AppIcon.JOURNAL, stringResource(R.string.help_logs_title),
                showConnectionHelp, { showConnectionHelp = !showConnectionHelp }, "help_connection_toggle") {
                BodyText(stringResource(R.string.help_logs_body))
                Spacer(Modifier.height(12.dp))
                BodyText(stringResource(R.string.help_warnings_body), Modifier.testTag("help_route_warnings"))
                Spacer(Modifier.height(12.dp))
                BodyText(stringResource(R.string.help_media_body), Modifier.testTag("help_media"))
                Spacer(Modifier.height(12.dp))
                BodyText(stringResource(R.string.help_report_body))
                TextButton(onClick = { onNavigate(2) }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("help_journal")) {
                    Text(stringResource(R.string.help_journal_button))
                }
            }
        }
        item(key = "help_background") {
            HelpTopic(AppIcon.DEVICE, stringResource(R.string.help_background_title),
                showBackgroundHelp, { showBackgroundHelp = !showBackgroundHelp }, "help_background_toggle") {
                BodyText(stringResource(R.string.help_background_body))
                OutlinedButton(onClick = actions.onOpenNotificationSettings,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("help_notifications")) {
                    Text(stringResource(R.string.help_notifications_button))
                }
                OutlinedButton(onClick = actions.onOpenBatterySettings,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("help_battery")) {
                    Text(stringResource(R.string.help_battery_button))
                }
                TextButton(onClick = { showDevices = !showDevices },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("help_devices")) {
                    Text(stringResource(R.string.help_device_toggle))
                }
                if (showDevices) {
                    BodyText(stringResource(R.string.help_samsung_body), Modifier.testTag("help_samsung"))
                    Spacer(Modifier.height(12.dp))
                    BodyText(stringResource(R.string.help_xiaomi_body), Modifier.testTag("help_xiaomi"))
                    Spacer(Modifier.height(12.dp))
                    BodyText(stringResource(R.string.help_menus_vary))
                }
            }
        }
        item(key = "help_helper") {
            HelpTopic(AppIcon.ROUTES, stringResource(R.string.help_routes_title),
                showHelperHelp, { showHelperHelp = !showHelperHelp }, "help_helper_toggle") {
                BodyText(stringResource(R.string.help_routes_body))
                Spacer(Modifier.height(12.dp))
                BodyText(stringResource(R.string.help_routes_owner_body))
                TextButton(onClick = { onNavigate(1) }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("help_routes")) {
                    Text(stringResource(R.string.help_routes_button))
                }
                OutlinedButton(onClick = onImportLink,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("import_link_help")) {
                    Text(stringResource(R.string.link_open))
                }
            }
        }
        item(key = "help_version") {
            Text(stringResource(R.string.ui_app_version, BuildConfig.VERSION_NAME),
                style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag("app_version"))
        }
    }
}

@Composable
private fun HelpTopic(
    icon: AppIcon,
    title: String,
    expanded: Boolean,
    onToggle: () -> Unit,
    tag: String,
    content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit,
) {
    val expansionDescription = stringResource(if (expanded) R.string.help_expanded else R.string.help_collapsed)
    AppCard {
        TextButton(
            onClick = onToggle,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag(tag)
                .semantics { stateDescription = expansionDescription },
            contentPadding = PaddingValues(0.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Glyph(icon, Modifier.size(22.dp))
                Text(title, modifier = Modifier.weight(1f), style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold)
                Glyph(if (expanded) AppIcon.CHEVRON_UP else AppIcon.CHEVRON_DOWN, Modifier.size(20.dp))
            }
        }
        if (expanded) {
            Spacer(Modifier.height(10.dp))
            content()
        }
    }
}

@Composable
private fun AppHeader() {
    val resources = LocalContext.current.resources
    // Keep the owner's original artwork intact; decode only a small header thumbnail.
    val brandLogo = remember(resources) {
        BitmapFactory.decodeResource(resources, R.drawable.header_byshadow64, BitmapFactory.Options().apply {
            inSampleSize = 4
            inScaled = false
        }).asImageBitmap()
    }
    Row(
        Modifier.fillMaxWidth().statusBarsPadding().padding(horizontal = 20.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Image(
            bitmap = brandLogo,
            contentDescription = null,
            modifier = Modifier.size(40.dp).clip(CircleShape)
                .border(1.dp, MaterialTheme.colorScheme.outlineVariant, CircleShape)
                .testTag("header_brand_logo"),
        )
        Column(Modifier.weight(1f)) {
            Text(
                stringResource(R.string.ui_app_title),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
            )
            Text(
                stringResource(R.string.ui_byline),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                stringResource(R.string.ui_dev_disclaimer),
                modifier = Modifier.testTag("dev_disclaimer"),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun Overview(state: TgProxyUiState, actions: TgProxyActions, modifier: Modifier) {
    val running = state.status == ProxyStatus.RUNNING
    val busy = state.status == ProxyStatus.STARTING || state.status == ProxyStatus.STOPPING ||
        state.isSaving || state.pairingStatus == PairingStatus.CONNECTING ||
        state.sshSetup.phase in setOf(SshSetupPhase.PROBING, SshSetupPhase.CONFIRM_HOST_KEY,
            SshSetupPhase.READY, SshSetupPhase.DEPLOYING, SshSetupPhase.VERIFYING)
    LazyColumn(
        modifier.fillMaxSize().testTag("overview_content"),
        contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 8.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item { StatusHero(state) }
        if (state.update.phase in setOf(io.github.byshadow64.tgproxy.UpdatePhase.AVAILABLE,
            io.github.byshadow64.tgproxy.UpdatePhase.DOWNLOADING, io.github.byshadow64.tgproxy.UpdatePhase.VERIFYING,
            io.github.byshadow64.tgproxy.UpdatePhase.READY, io.github.byshadow64.tgproxy.UpdatePhase.INSTALLING,
            io.github.byshadow64.tgproxy.UpdatePhase.CONFIRM)) {
            item(key = "overview_update") { UpdateCard(state.update, actions) }
        }
        item {
            Button(
                onClick = if (running) actions.onStop else actions.onStart,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp).testTag("proxy_action"),
                shape = RoundedCornerShape(18.dp),
                contentPadding = PaddingValues(horizontal = 20.dp, vertical = 16.dp),
                colors = if (running) ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.secondaryContainer,
                    contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
                ) else ButtonDefaults.buttonColors(),
            ) {
                if (busy) {
                    CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                } else {
                    Glyph(if (running) AppIcon.STOP else AppIcon.PLAY, Modifier.size(20.dp))
                }
                Spacer(Modifier.width(10.dp))
                Text(
                    stringResource(if (busy) R.string.ui_please_wait else if (running) R.string.ui_stop else R.string.ui_start),
                    style = MaterialTheme.typography.titleSmall,
                )
            }
        }
        state.statusMessage?.let { message -> item { Notice(message, state.status == ProxyStatus.ERROR) } }
        item { TelegramConnectionCard(running, actions) }
        item {
            Column(Modifier.testTag("session_metrics"), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                AppCard {
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(stringResource(R.string.ui_active_connections), style = MaterialTheme.typography.bodyMedium)
                            Spacer(Modifier.height(6.dp))
                            Text(
                                stringResource(R.string.ui_route_counts, state.metrics.directConnections, state.metrics.helperConnections),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Text(
                            NumberFormat.getIntegerInstance().format(state.metrics.activeConnections.coerceAtLeast(0)),
                            style = MaterialTheme.typography.headlineLarge,
                            color = MaterialTheme.colorScheme.primary,
                            fontWeight = FontWeight.SemiBold,
                            modifier = Modifier.padding(start = 12.dp),
                        )
                    }
                    HorizontalDivider(Modifier.padding(vertical = 18.dp), color = MaterialTheme.colorScheme.outlineVariant)
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                        TrafficMetric(stringResource(R.string.ui_received), state.metrics.bytesReceived, AppIcon.DOWN, Modifier.weight(1f))
                        TrafficMetric(stringResource(R.string.ui_sent), state.metrics.bytesSent, AppIcon.UP, Modifier.weight(1f))
                    }
                }
            }
        }
    }
}

@Composable
private fun TelegramConnectionCard(running: Boolean, actions: TgProxyActions) {
    AppCard {
        CardHeading(AppIcon.TELEGRAM, stringResource(R.string.ui_telegram_title))
        BodyText(stringResource(R.string.ui_telegram_body))
        Spacer(Modifier.height(12.dp))
        OutlinedButton(
            onClick = actions.onOpenTelegram,
            enabled = running,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("open_telegram"),
            shape = RoundedCornerShape(14.dp),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
        ) { Text(stringResource(R.string.ui_open_telegram)) }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(
            onClick = actions.onCopyTelegramLink,
            enabled = running,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("copy_telegram_link"),
            shape = RoundedCornerShape(14.dp),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
        ) {
            Glyph(AppIcon.COPY, Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.ui_copy_telegram_link))
        }
        if (!running) {
            Spacer(Modifier.height(8.dp))
            Text(
                stringResource(R.string.ui_telegram_stopped_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun StatusHero(state: TgProxyUiState) {
    val primary = MaterialTheme.colorScheme.primary
    val container = MaterialTheme.colorScheme.primaryContainer
    val titles = when (state.status) {
        ProxyStatus.STOPPED -> R.string.ui_status_stopped to R.string.ui_status_stopped_body
        ProxyStatus.STARTING -> R.string.ui_status_starting to R.string.ui_status_starting_body
        ProxyStatus.RUNNING -> R.string.ui_status_running to R.string.ui_status_running_body
        ProxyStatus.STOPPING -> R.string.ui_status_stopping to R.string.ui_status_stopping_body
        ProxyStatus.ERROR -> R.string.ui_status_error to R.string.ui_status_error_body
    }
    Column(
        Modifier.fillMaxWidth()
            .clip(RoundedCornerShape(20.dp))
            .background(Brush.linearGradient(listOf(container, container.copy(alpha = 0.45f))))
            .border(1.dp, primary.copy(alpha = 0.14f), RoundedCornerShape(20.dp))
            .padding(16.dp)
            .semantics { liveRegion = LiveRegionMode.Polite },
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Box(Modifier.size(8.dp).clip(CircleShape).background(
                when (state.status) {
                    ProxyStatus.RUNNING -> primary
                    ProxyStatus.ERROR -> MaterialTheme.colorScheme.error
                    else -> MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                },
            ))
            Text(
                stringResource(titles.first),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.semantics { heading() },
            )
        }
        Text(stringResource(titles.second), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        val port = if (state.status == ProxyStatus.RUNNING) state.runningPort?.toString() else state.settings.localPort
        if (port != null) Text(
            stringResource(R.string.ui_endpoint, port),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.testTag("proxy_endpoint"),
        )
    }
}

@Composable
private fun TrafficMetric(label: String, bytes: Long, icon: AppIcon, modifier: Modifier) {
    Column(modifier, verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
            Glyph(icon, Modifier.size(16.dp), MaterialTheme.colorScheme.primary)
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text(formatBytes(bytes), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun Routes(
    state: TgProxyUiState,
    draft: ProxySettingsUi,
    onDraftChange: (ProxySettingsUi) -> Unit,
    helperIp: String,
    onHelperIpChange: (String) -> Unit,
    actions: TgProxyActions,
    onImportLink: () -> Unit,
    modifier: Modifier,
) {
    val running = state.status == ProxyStatus.RUNNING
    val busy = state.status == ProxyStatus.STARTING || state.status == ProxyStatus.STOPPING ||
        state.isSaving || state.pairingStatus == PairingStatus.CONNECTING ||
        state.sshSetup.phase in setOf(SshSetupPhase.PROBING, SshSetupPhase.CONFIRM_HOST_KEY,
            SshSetupPhase.READY, SshSetupPhase.DEPLOYING, SshSetupPhase.VERIFYING)
    val dirty = draft != state.settings
    var showRestartDialog by remember { mutableStateOf(false) }
    var showSsh by remember { mutableStateOf(state.sshSetup.phase != SshSetupPhase.INPUT) }
    if (showRestartDialog) {
        AlertDialog(
            onDismissRequest = { showRestartDialog = false },
            title = { Text(stringResource(R.string.ui_restart_title)) },
            text = { Text(stringResource(R.string.ui_restart_body)) },
            confirmButton = {
                TextButton(enabled = !busy, modifier = Modifier.heightIn(min = 48.dp), onClick = {
                    showRestartDialog = false
                    actions.onRestartWithSettings(draft.copy())
                }) { Text(stringResource(R.string.ui_restart_confirm)) }
            },
            dismissButton = {
                TextButton(modifier = Modifier.heightIn(min = 48.dp), onClick = { showRestartDialog = false }) { Text(stringResource(R.string.ui_cancel)) }
            },
        )
    }
    LazyColumn(
        modifier.fillMaxSize().imePadding().testTag("routes_content"),
        contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 8.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            ScreenTitle(stringResource(R.string.ui_routes_title), stringResource(R.string.routes_simple_subtitle))
        }
        item {
            RegistryHelperCard(state, helperIp, onHelperIpChange, actions)
        }
        item {
            OutlinedButton(onClick = onImportLink, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("import_link_routes")) {
                Text(stringResource(R.string.link_open))
            }
        }
        if (state.registrySetupRequired || state.sshSetup.phase != SshSetupPhase.INPUT) {
            item {
                AppCard {
                    CardHeading(AppIcon.LOCK, stringResource(R.string.routes_ssh_title))
                    BodyText(stringResource(R.string.routes_ssh_body))
                    TextButton(onClick = { showSsh = !showSsh },
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("helper_setup_instructions")) {
                        Text(stringResource(R.string.registry_setup))
                    }
                    if (showSsh) HelperSshSetup(state, helperIp, actions)
                }
            }
        }
        if (state.settings.helperHost.isNotBlank()) {
            item {
                AppCard {
                    CardHeading(AppIcon.LOCK, stringResource(if (state.settings.helperRegistryManaged)
                        R.string.routes_saved_helper else R.string.routes_saved_private))
                    val endpoint = if (':' in state.settings.helperHost) "[" + state.settings.helperHost + "]:" + state.settings.helperPort
                        else state.settings.helperHost + ":" + state.settings.helperPort
                    Text(endpoint, modifier = Modifier.testTag("saved_helper_summary"), fontFamily = FontFamily.Monospace)
                    if (state.settings.helperRegistryManaged) {
                        Spacer(Modifier.height(12.dp))
                        BodyText(stringResource(R.string.routes_ready_status))
                        val shareable = remember(state.settings.helperHost) {
                            runCatching { ProxyLinkParser.helperLink(state.settings.helperHost) }.getOrNull()
                        }
                        if (shareable != null) {
                            TextButton(onClick = { actions.onCopyHelperLink(shareable) },
                                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("copy_helper_link")) {
                                Glyph(AppIcon.COPY, Modifier.size(18.dp))
                                Spacer(Modifier.width(8.dp))
                                Text(stringResource(R.string.link_copy_helper))
                            }
                        }
                    } else {
                        Spacer(Modifier.height(12.dp))
                        BodyText(stringResource(R.string.routes_private_preserved))
                    }
                    val toggleLabel = stringResource(R.string.ui_helper_toggle)
                    Row(Modifier.fillMaxWidth().heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(toggleLabel, Modifier.weight(1f), style = MaterialTheme.typography.titleSmall)
                        Switch(checked = draft.helperEnabled, onCheckedChange = { onDraftChange(draft.copy(helperEnabled = it)) },
                            enabled = !busy, modifier = Modifier.testTag("helper_toggle").semantics { contentDescription = toggleLabel })
                    }
                }
            }
        }
        item {
            AppCard {
                CardHeading(AppIcon.DEVICE, stringResource(R.string.ui_listener_title))
                SettingsField(
                    value = draft.localPort,
                    onValueChange = { onDraftChange(draft.copy(localPort = it.take(5))) },
                    label = stringResource(R.string.ui_local_port_label),
                    field = SettingsFields.LOCAL_PORT,
                    hint = stringResource(R.string.ui_port_hint),
                    error = state.validationErrors[SettingsFields.LOCAL_PORT],
                    keyboardType = KeyboardType.Number,
                    enabled = !busy,
                )
            }
        }
        item {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(if (dirty) R.string.ui_unsaved else if (state.hasSavedSettings) R.string.ui_saved else R.string.ui_not_saved),
                    style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(stringResource(if (running) R.string.ui_running_settings_hint else R.string.ui_stopped_settings_hint),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Button(onClick = { if (running) showRestartDialog = true else actions.onSaveSettings(draft.copy()) },
                    enabled = !busy && (dirty || !state.hasSavedSettings),
                    modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp).testTag("save_settings"), shape = RoundedCornerShape(16.dp),
                    contentPadding = PaddingValues(16.dp)) {
                    if (state.isSaving) {
                        CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(10.dp))
                    }
                    Text(stringResource(if (state.isSaving) R.string.ui_saving else if (running) R.string.ui_restart_apply else R.string.ui_save))
                }
            }
        }
    }
}

@Composable
private fun RegistryHelperCard(
    state: TgProxyUiState,
    host: String,
    onHostChange: (String) -> Unit,
    actions: TgProxyActions,
) {
    val connecting = state.pairingStatus == PairingStatus.CONNECTING
    val stopped = state.status == ProxyStatus.STOPPED || state.status == ProxyStatus.ERROR
    val sshLocked = state.sshSetup.phase in setOf(SshSetupPhase.PROBING, SshSetupPhase.CONFIRM_HOST_KEY, SshSetupPhase.READY, SshSetupPhase.DEPLOYING, SshSetupPhase.VERIFYING)
    val enabled = stopped && !connecting && !state.isSaving && !sshLocked
    AppCard {
        CardHeading(AppIcon.LOCK, stringResource(R.string.routes_ip_title))
        BodyText(stringResource(R.string.routes_ip_body))
        Spacer(Modifier.height(16.dp))
        SettingsField(
            value = host,
            onValueChange = { onHostChange(it.take(128)) },
            label = stringResource(R.string.registry_ip),
            field = PairingFields.HOST,
            error = state.pairingValidationErrors[PairingFields.HOST],
            keyboardType = KeyboardType.Uri,
            enabled = enabled,
        )
        if (!stopped) {
            Spacer(Modifier.height(12.dp))
            BodyText(stringResource(R.string.registry_stop_first))
        }
        // A previous successful registration does not verify a newly typed IP.
        val message = state.pairingMessage.takeUnless {
            state.pairingStatus == PairingStatus.SUCCESS && host.trim() != state.settings.helperHost
        }
        message?.let {
            Spacer(Modifier.height(12.dp))
            Text(it, style = MaterialTheme.typography.bodyMedium,
                color = if (state.pairingStatus == PairingStatus.ERROR) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }.testTag("registry_message"))
        }
        Spacer(Modifier.height(16.dp))
        Button(onClick = { actions.onConnectHelperIp(host.trim()) }, enabled = enabled,
            modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp).testTag("connect_helper_ip"), shape = RoundedCornerShape(16.dp)) {
            if (connecting) {
                CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(10.dp))
            }
            Text(stringResource(if (connecting) R.string.ui_pair_connecting else R.string.registry_connect))
        }
        if (connecting) {
            TextButton(onClick = actions.onCancelHelperConnect, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("cancel_helper_ip")) {
                Text(stringResource(R.string.registry_cancel))
            }
        }

    }
}

@Composable
private fun SettingsField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    field: String,
    hint: String? = null,
    error: String? = null,
    keyboardType: KeyboardType = KeyboardType.Text,
    enabled: Boolean = true,
    singleLine: Boolean = true,
    monospace: Boolean = false,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        supportingText = if (error != null || hint != null) { { Text(error ?: hint.orEmpty()) } } else null,
        isError = error != null,
        enabled = enabled,
        singleLine = singleLine,
        minLines = 1,
        maxLines = if (singleLine) 1 else 4,
        keyboardOptions = KeyboardOptions(
            capitalization = KeyboardCapitalization.None,
            autoCorrectEnabled = false,
            keyboardType = keyboardType,
            imeAction = ImeAction.Next,
        ),
        textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default),
        modifier = Modifier.fillMaxWidth().testTag("field_$field"),
        shape = RoundedCornerShape(14.dp),
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun Journal(state: TgProxyUiState, actions: TgProxyActions, modifier: Modifier) {
    var filter by rememberSaveable { mutableIntStateOf(0) }
    val levels = listOf(null, LogLevel.INFO, LogLevel.WARNING, LogLevel.ERROR)
    val labels = listOf(R.string.ui_filter_all, R.string.ui_filter_info, R.string.ui_filter_warning, R.string.ui_filter_error)
    val boundedEntries = state.journal.takeLast(200)
    val entries = boundedEntries.asReversed().filter { levels[filter] == null || it.level == levels[filter] }

    LazyColumn(
        modifier.fillMaxSize().testTag("journal_content"),
        contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 8.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            ScreenTitle(stringResource(R.string.ui_journal_title), stringResource(R.string.ui_journal_subtitle))
            Spacer(Modifier.height(14.dp))
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                labels.forEachIndexed { index, label ->
                    val filterColor = levels[index]?.let { logColor(it) } ?: MaterialTheme.colorScheme.onSurfaceVariant
                    FilterChip(
                        selected = filter == index,
                        onClick = { filter = index },
                        label = { Text(stringResource(label)) },
                        colors = FilterChipDefaults.filterChipColors(
                            labelColor = filterColor,
                            selectedLabelColor = filterColor,
                            selectedContainerColor = filterColor.copy(alpha = 0.14f),
                        ),
                        modifier = Modifier.heightIn(min = 48.dp).testTag("journal_filter_$index"),
                    )
                }
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = actions.onCopyJournal, enabled = boundedEntries.isNotEmpty(), modifier = Modifier.heightIn(min = 48.dp)) {
                    Glyph(AppIcon.COPY, Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.ui_copy_journal))
                }
                TextButton(onClick = actions.onClearJournal, enabled = boundedEntries.isNotEmpty(), modifier = Modifier.heightIn(min = 48.dp)) {
                    Text(stringResource(R.string.ui_clear_journal))
                }
            }
        }
        if (entries.isEmpty()) {
            item {
                AppCard {
                    Spacer(Modifier.height(12.dp))
                    Glyph(AppIcon.JOURNAL, Modifier.size(30.dp), MaterialTheme.colorScheme.primary)
                    Spacer(Modifier.height(16.dp))
                    Text(
                        stringResource(if (boundedEntries.isEmpty()) R.string.ui_empty_journal_title else R.string.ui_empty_filter_title),
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Spacer(Modifier.height(6.dp))
                    BodyText(stringResource(if (boundedEntries.isEmpty()) R.string.ui_empty_journal_body else R.string.ui_empty_filter_body))
                    Spacer(Modifier.height(12.dp))
                }
            }
        } else {
            items(entries, key = { it.id }) { entry -> JournalEvent(entry) }
        }
    }
}

@Composable
private fun JournalEvent(entry: JournalEntry) {
    val color = logColor(entry.level)
    val levelLabel = stringResource(when (entry.level) {
        LogLevel.INFO -> R.string.ui_event_info
        LogLevel.WARNING -> R.string.ui_event_warning
        LogLevel.ERROR -> R.string.ui_event_error
    })
    Surface(modifier = Modifier.testTag("journal_event_${entry.id}"), shape = RoundedCornerShape(18.dp), color = MaterialTheme.colorScheme.surface) {
        Row(Modifier.fillMaxWidth().padding(16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Box(Modifier.padding(top = 6.dp).size(7.dp).clip(CircleShape).background(color))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    "$levelLabel · ${entry.timestamp}",
                    style = MaterialTheme.typography.labelSmall,
                    color = color,
                )
                Text(entry.message, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
private fun logColor(level: LogLevel): Color = when (level) {
    LogLevel.INFO -> MaterialTheme.colorScheme.primary
    LogLevel.WARNING -> if (MaterialTheme.colorScheme.background.luminance() < 0.3f) Color(0xFFE8BE73) else Color(0xFF8A5900)
    LogLevel.ERROR -> MaterialTheme.colorScheme.error
}

@Composable
private fun AppCard(content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) { Column(Modifier.padding(20.dp), content = content) }
}

@Composable
private fun CardHeading(icon: AppIcon, title: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        Glyph(icon, Modifier.size(22.dp), MaterialTheme.colorScheme.primary)
        Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
    }
    Spacer(Modifier.height(10.dp))
}

@Composable
private fun BodyText(text: String, modifier: Modifier = Modifier) {
    Text(text, modifier = modifier, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
private fun ScreenTitle(title: String, subtitle: String) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(title, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold, modifier = Modifier.semantics { heading() })
        BodyText(subtitle)
    }
}

@Composable
private fun SectionEyebrow(text: String) {
    Text(text, style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold, letterSpacing = 1.3.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
private fun Notice(text: String, error: Boolean) {
    Surface(
        color = if (error) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.secondaryContainer,
        contentColor = if (error) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onSecondaryContainer,
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth().semantics { liveRegion = LiveRegionMode.Polite },
    ) { Text(text, Modifier.padding(16.dp), style = MaterialTheme.typography.bodyMedium) }
}

@Composable
private fun formatBytes(value: Long): String {
    val bytes = value.coerceAtLeast(0)
    val unit: Int
    val amount: Double
    when {
        bytes >= (1L shl 30) -> { unit = R.string.ui_gib_unit; amount = bytes / (1L shl 30).toDouble() }
        bytes >= (1L shl 20) -> { unit = R.string.ui_mib_unit; amount = bytes / (1L shl 20).toDouble() }
        bytes >= (1L shl 10) -> { unit = R.string.ui_kib_unit; amount = bytes / (1L shl 10).toDouble() }
        else -> { unit = R.string.ui_bytes_unit; amount = bytes.toDouble() }
    }
    val formatter = NumberFormat.getNumberInstance().apply { maximumFractionDigits = if (bytes < 1024) 0 else 1 }
    return "${formatter.format(amount)} ${stringResource(unit)}"
}

private enum class AppIcon { OVERVIEW, ROUTES, JOURNAL, HELP, PLAY, STOP, TELEGRAM, DEVICE, LOCK, UP, DOWN, EYE, EYE_OFF, COPY, CHEVRON_UP, CHEVRON_DOWN }

/** Small original line icons, without a font or an extended icon dependency. */
@Composable
private fun Glyph(icon: AppIcon, modifier: Modifier = Modifier, color: Color = LocalContentColor.current) {
    Canvas(modifier.size(24.dp)) {
        val sx = size.width / 24f
        val sy = size.height / 24f
        val stroke = Stroke(width = 1.7f * sx, cap = StrokeCap.Round)
        fun point(x: Float, y: Float) = Offset(x * sx, y * sy)
        fun line(x1: Float, y1: Float, x2: Float, y2: Float) = drawLine(color, point(x1, y1), point(x2, y2), 1.7f * sx, StrokeCap.Round)
        fun box(x: Float, y: Float, w: Float, h: Float, r: Float = 1.5f) = drawRoundRect(color, point(x, y), Size(w * sx, h * sy), CornerRadius(r * sx), style = stroke)
        when (icon) {
            AppIcon.OVERVIEW -> { box(3f, 3f, 7f, 7f); box(14f, 3f, 7f, 7f); box(3f, 14f, 7f, 7f); box(14f, 14f, 7f, 7f) }
            AppIcon.ROUTES -> { line(4f, 7f, 20f, 7f); line(16f, 3f, 20f, 7f); line(20f, 7f, 16f, 11f); line(20f, 17f, 4f, 17f); line(4f, 17f, 8f, 13f); line(4f, 17f, 8f, 21f) }
            AppIcon.JOURNAL -> { box(4f, 3f, 16f, 18f, 2f); line(8f, 8f, 16f, 8f); line(8f, 12f, 16f, 12f); line(8f, 16f, 13f, 16f) }
            AppIcon.HELP -> {
                drawCircle(color, 9f * sx, point(12f, 12f), style = stroke)
                drawPath(Path().apply { moveTo(9f*sx, 9f*sy); cubicTo(9f*sx, 5f*sy, 17f*sx, 6f*sy, 15f*sx, 11f*sy); lineTo(12f*sx, 13f*sy); lineTo(12f*sx, 14f*sy) }, color, style = stroke)
                drawCircle(color, 0.9f*sx, point(12f, 17f))
            }
            AppIcon.PLAY -> { drawPath(Path().apply { moveTo(8f * sx, 4f * sy); lineTo(20f * sx, 12f * sy); lineTo(8f * sx, 20f * sy); close() }, color) }
            AppIcon.STOP -> drawRoundRect(color, point(5f, 5f), Size(14f * sx, 14f * sy), CornerRadius(2f * sx))
            AppIcon.TELEGRAM -> {
                val p = Path().apply { moveTo(3f * sx, 11f * sy); lineTo(21f * sx, 4f * sy); lineTo(17f * sx, 21f * sy); lineTo(10f * sx, 15f * sy); lineTo(3f * sx, 11f * sy); close() }
                drawPath(p, color, style = stroke); line(10f, 15f, 16f, 9f)
            }
            AppIcon.DEVICE -> { box(6f, 2f, 12f, 20f, 3f); line(10f, 18f, 14f, 18f) }
            AppIcon.LOCK -> { box(4f, 10f, 16f, 11f, 2f); drawArc(color, 180f, 180f, false, point(7f, 2f), Size(10f * sx, 16f * sy), style = stroke); line(12f, 14f, 12f, 17f) }
            AppIcon.UP -> { line(12f, 20f, 12f, 4f); line(6f, 10f, 12f, 4f); line(12f, 4f, 18f, 10f) }
            AppIcon.DOWN -> { line(12f, 4f, 12f, 20f); line(6f, 14f, 12f, 20f); line(12f, 20f, 18f, 14f) }
            AppIcon.EYE, AppIcon.EYE_OFF -> {
                val p = Path().apply { moveTo(2f * sx, 12f * sy); quadraticTo(12f * sx, 0f, 22f * sx, 12f * sy); quadraticTo(12f * sx, 24f * sy, 2f * sx, 12f * sy) }
                drawPath(p, color, style = stroke); drawCircle(color, 3f * sx, point(12f, 12f), style = stroke)
                if (icon == AppIcon.EYE_OFF) line(3f, 3f, 21f, 21f)
            }
            AppIcon.COPY -> { box(8f, 7f, 12f, 14f, 2f); line(4f, 17f, 4f, 3f); line(4f, 3f, 15f, 3f) }
            AppIcon.CHEVRON_UP -> { line(5f, 15f, 12f, 8f); line(12f, 8f, 19f, 15f) }
            AppIcon.CHEVRON_DOWN -> { line(5f, 9f, 12f, 16f); line(12f, 16f, 19f, 9f) }
        }
    }
}
