package io.github.byshadow64.tgproxy

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.net.Uri
import android.provider.Settings
import android.view.View
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import io.github.byshadow64.tgproxy.ui.TgProxyActions
import io.github.byshadow64.tgproxy.ui.TgProxyApp
import io.github.byshadow64.tgproxy.ui.TelegramProxyLink
import io.github.byshadow64.tgproxy.ui.HelperIpLink
import io.github.byshadow64.tgproxy.ui.ProxyLinkParser

class MainActivity : ComponentActivity() {
    private val connectionMonitor by lazy { ConnectionMonitor(this) }
    private var pendingForegroundAction: (() -> Unit)? = null
    private var updatesRequest by mutableStateOf(0)
    private var incomingHelperLink by mutableStateOf<HelperIpLink?>(null)
    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        val action = pendingForegroundAction; pendingForegroundAction = null
        if (lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) action?.invoke()
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        AppRuntime.initialize(this)
        UpdateManager.initialize(this)
        acceptUpdateIntent(intent)
        acceptHelperLink(intent)
        setContent {
            val updateState = UpdateManager.state.collectAsStateWithLifecycle().value
            val connection = connectionMonitor.state.collectAsStateWithLifecycle().value
            androidx.compose.runtime.LaunchedEffect(updateState.phase) {
                if (updateState.phase == UpdatePhase.CONFIRM && lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) openUpdateInstaller()
            }
            val state = AppRuntime.state.collectAsStateWithLifecycle().value.copy(incomingHelperLink = incomingHelperLink, update = updateState, connection = connection)
            TgProxyApp(state, TgProxyActions(
                onFeedbackConsumed = { AppRuntime.consumeFeedback(it) },
                onCheckUpdate = { UpdateManager.check() },
                onDownloadUpdate = { UpdateManager.download() },
                onCancelUpdate = { UpdateManager.cancel() },
                onInstallUpdate = { openUpdateInstaller() },
                onUpdateOptions = { auto, wifi -> UpdateManager.options(auto, wifi) },
                onStart = { requestStart(ProxyService.ACTION_START) },
                onReconnect = {
                    if (AppRuntime.state.value.status == io.github.byshadow64.tgproxy.ui.ProxyStatus.RUNNING)
                        requestStart(ProxyService.ACTION_RECONNECT)
                },
                onStop = { launchService(ProxyService.ACTION_STOP) },
                onOpenTelegram = { openTelegram() },
                onCopyTelegramLink = { copyTelegramLink() },
                onSaveSettings = { AppRuntime.save(it) },
                onConnectHelperIp = { host -> requestForegroundPermission { AppRuntime.connectHelperIp(host) } },
                onCancelHelperConnect = { AppRuntime.cancelHelperConnect() },
                onOpenImportedTelegramProxy = { openImportedTelegramProxy(it) },
                onOpenNotificationSettings = { openNotificationSettings() },
                onOpenBatterySettings = { openAppSettings() },
                onConsumeIncomingHelperLink = { incomingHelperLink = null },
                onCopyHelperLink = { link ->
                    getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("TG Proxy Helper", link.uri))
                    AppRuntime.showMessage(R.string.link_copied)
                },
                onProbeHelperSsh = { host, port, user -> requestForegroundPermission { AppRuntime.probeHelperSsh(host, port, user) } },
                onConfirmHelperSshKey = { AppRuntime.confirmHelperSshKey() },
                onDeployHelperSsh = { password, registered, upgrade -> AppRuntime.deployHelperSsh(password, registered, upgrade) },
                onCancelHelperSsh = { AppRuntime.cancelHelperSsh() },
                onResetHelperSsh = { AppRuntime.resetHelperSsh() },
                onRestartWithSettings = { ui -> AppRuntime.save(ui) {
                    if (lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) requestStart(ProxyService.ACTION_RESTART)
                    else AppRuntime.showMessage(R.string.service_saved_restart)
                } },
                onClearJournal = { AppRuntime.clearJournal() },
                onCopyJournal = {
                    val clipboard = getSystemService(ClipboardManager::class.java)
                    clipboard.setPrimaryClip(ClipData.newPlainText("TG Proxy", AppRuntime.journalReport()))
                    AppRuntime.showMessage(R.string.service_report_copied)
                },
            ), updatesRequest)
        }
    }
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        acceptUpdateIntent(intent)
        acceptHelperLink(intent)
    }
    override fun onResume() {
        super.onResume()
        UpdateManager.foreground()
        if (UpdateManager.state.value.phase == UpdatePhase.CONFIRM) openUpdateInstaller()
    }
    private fun acceptUpdateIntent(request: Intent?) {
        if (request?.getBooleanExtra("show_updates", false) == true) {
            updatesRequest++
            request.removeExtra("show_updates")
        }
    }
    override fun onStart() {
        super.onStart()
        connectionMonitor.start()
    }
    override fun onStop() {
        connectionMonitor.stop()
        super.onStop()
    }
    private fun openUpdateInstaller() {
        if (!lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) return
        if (UpdateManager.state.value.phase == UpdatePhase.CONFIRM) {
            val next = UpdateManager.takeConfirmation() ?: return
            try { startActivity(next) } catch (_: Exception) { UpdateManager.confirmationUnavailable() }
        } else if (!packageManager.canRequestPackageInstalls()) {
            try { startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:$packageName"))) }
            catch (_: Exception) { UpdateManager.confirmationUnavailable() }
        } else UpdateManager.install()
    }
    private fun acceptHelperLink(request: Intent?) {
        if (request?.action != Intent.ACTION_VIEW) return
        val parsed = request.dataString?.let { value -> try { ProxyLinkParser.parse(value) } catch (_: Exception) { null } }
        if (parsed is HelperIpLink) incomingHelperLink = parsed
        // Input only opens a RAM-only preview. Do not reapply an old link on activity recreation.
        // Keep the original launcher identity while removing an incoming URI. This also
        // preserves lifecycle observers across singleTop handoffs and prevents replay.
        setIntent(Intent(intent).setData(null))
    }
    private fun requestStart(action: String) {
        if (!AppRuntime.canStart()) return
        requestForegroundPermission { launchService(action) }
    }
    private fun requestForegroundPermission(action: () -> Unit) {
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED && !shouldShowRequestPermissionRationale(Manifest.permission.POST_NOTIFICATIONS)) {
            pendingForegroundAction = action
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else if (lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) action()
    }
    private fun launchService(action: String) {
        try {
            val intent = Intent(this, ProxyService::class.java).setAction(action)
            if (action == ProxyService.ACTION_STOP) startService(intent) else ContextCompat.startForegroundService(this, intent)
        } catch (_: Exception) { AppRuntime.showMessage(R.string.service_start_error) }
    }
    internal fun openTelegram() {
        val uri = AppRuntime.telegramUri() ?: run { AppRuntime.showMessage(R.string.service_start_first); return }
        openProxyLink(uri)
    }
    internal fun copyTelegramLink() {
        val uri = AppRuntime.telegramUri(web = true) ?: run { AppRuntime.showMessage(R.string.service_start_first); return }
        val clip = ClipData.newPlainText("TG Proxy", uri.toString())
        // The connection link contains this phone's local proxy secret. Suppress
        // clipboard previews on Android versions that support this standard flag.
        clip.description.extras = PersistableBundle().apply {
            putBoolean("android.content.extra.IS_SENSITIVE", true)
        }
        getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
        AppRuntime.showMessage(R.string.link_proxy_copied)
    }
    private fun openImportedTelegramProxy(link: TelegramProxyLink) {
        if (link.isLoopback) { openTelegram(); return }
        openProxyLink(Uri.parse(link.uri))
    }
    private fun openNotificationSettings() {
        try { startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, packageName)) }
        catch (_: Exception) { openAppSettings() }
    }
    private fun openAppSettings() {
        try { startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", packageName, null))) }
        catch (_: Exception) { /* OEM settings may be unavailable; do not request an automatic exemption. */ }
    }
    private fun openProxyLink(uri: Uri) {
        val request = Intent(Intent.ACTION_VIEW, uri).addCategory(Intent.CATEGORY_BROWSABLE)
        try { startActivity(Intent.createChooser(request, getString(R.string.ui_open_telegram))) }
        catch (_: Exception) { AppRuntime.showMessage(R.string.service_telegram_missing) }
    }
}
