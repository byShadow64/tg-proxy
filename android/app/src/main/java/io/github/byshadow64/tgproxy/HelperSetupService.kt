package io.github.byshadow64.tgproxy

import android.app.*
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.PowerManager
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.collectLatest

/** One explicit RAM-only setup task. Restarted/duplicate intents cannot reconstruct credentials or rerun it. */
class HelperSetupService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    @Volatile private var activeRun: Long? = null
    private var operation: Job? = null
    private var notifications: Job? = null
    @Volatile private var destroyed = false
    @Volatile private var latestStartId = 0
    private var waitingRun: Long? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var lastNoticeAt = 0L
    private var lastNoticeText: String? = null
    override fun onCreate() {
        super.onCreate(); AppRuntime.initialize(this)
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, getString(R.string.ssh_setup_title), NotificationManager.IMPORTANCE_LOW))
    }
    @Synchronized override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Notification actions are service starts too. Cleanup must acknowledge the action's
        // newer id, otherwise stopSelf(the original job id) leaves an empty service alive.
        latestStartId = startId
        val run = intent?.getLongExtra(EXTRA_RUN, -1) ?: -1
        if (intent?.action == ACTION_CANCEL) {
            if (activeRun == run) AppRuntime.cancelHelperSsh(run)
            if (activeRun == null) stopSelf(startId)
            return START_NOT_STICKY
        }
        if (intent?.action != ACTION_START || run < 0) {
            // Even an invalid request may have arrived via startForegroundService.
            // Promote before rejecting it so Android never waits for a missing foreground ack.
            if (activeRun == null) begin(-1, startId)
            return START_NOT_STICKY
        }
        if (activeRun == run || waitingRun == run) return START_NOT_STICKY
        if (activeRun != null) {
            if (!AppRuntime.hasQueuedSshTask(run)) return START_NOT_STICKY
            waitingRun = run
            val previous = operation
            scope.launch {
                previous?.join()
                withContext(Dispatchers.Main) {
                    waitingRun = null
                    if (destroyed) AppRuntime.abandonSshTask(run) else begin(run, startId)
                }
            }
        } else begin(run, startId)
        return START_NOT_STICKY
    }
    @Synchronized private fun begin(run: Long, startId: Int) {
        if (destroyed) { AppRuntime.abandonSshTask(run); return }
        try {
            if (Build.VERSION.SDK_INT >= 29) startForeground(NOTIFICATION_ID, notification(run), ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
            else startForeground(NOTIFICATION_ID, notification(run))
            val task = AppRuntime.takeSshTask(run)
            if (task == null) { stopForeground(STOP_FOREGROUND_REMOVE); stopSelf(startId); return }
            activeRun = run
            wakeLock = getSystemService(PowerManager::class.java).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "TGProxy:HelperSetup").apply {
                setReferenceCounted(false); acquire(WAKE_TIMEOUT_MS)
            }
            notifications = scope.launch {
                AppRuntime.state.collectLatest { updateNotification(run) }
            }
            operation = scope.launch {
                try { task() } finally { finish(run) }
            }
        } catch (_: Exception) {
            AppRuntime.abandonSshTask(run)
            if (activeRun == run) finish(run) else { stopForeground(STOP_FOREGROUND_REMOVE); stopSelf(startId) }
        }
    }
    @Synchronized private fun finish(run: Long) {
        if (activeRun != run) return
        notifications?.cancel(); activeRun = null
        wakeLock?.let { if (it.isHeld) it.release() }; wakeLock = null
        if (!destroyed) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            // A separately queued next operation owns its start request and begins after join().
            if (waitingRun == null) stopSelfResult(latestStartId)
        }
    }
    @Synchronized private fun updateNotification(run: Long) {
        if (destroyed || activeRun != run) return
        val now = android.os.SystemClock.elapsedRealtime()
        val text = AppRuntime.state.value.sshSetup.progressMessage
        if (text == lastNoticeText && now - lastNoticeAt < 250) return
        lastNoticeAt = now; lastNoticeText = text
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(run))
    }
    private fun notification(run: Long): Notification {
        val open = PendingIntent.getActivity(this, 3501, Intent(this, MainActivity::class.java), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val cancel = PendingIntent.getService(this, 3502, Intent(this, HelperSetupService::class.java).setAction(ACTION_CANCEL).putExtra(EXTRA_RUN, run),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val state = AppRuntime.state.value.sshSetup
        return NotificationCompat.Builder(this, CHANNEL).setSmallIcon(R.drawable.ic_proxy_notification)
            .setContentTitle(getString(R.string.ssh_setup_title)).setContentText(state.progressMessage ?: getString(R.string.ssh_connecting))
            .setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true)
            .setProgress(100, state.percent ?: 0, state.percent == null)
            .addAction(0, getString(R.string.ui_cancel), cancel).build()
    }
    @Synchronized override fun onDestroy() {
        destroyed = true
        waitingRun?.let { AppRuntime.abandonSshTask(it) }; waitingRun = null
        activeRun?.let { AppRuntime.cancelHelperSsh(it); AppRuntime.abandonSshTask(it) }
        notifications?.cancel(); scope.cancel()
        wakeLock?.let { if (it.isHeld) it.release() }; wakeLock = null
        stopForeground(STOP_FOREGROUND_REMOVE); super.onDestroy()
    }
    override fun onTimeout(startId: Int, fgsType: Int) {
        activeRun?.let { AppRuntime.cancelHelperSsh(it); AppRuntime.abandonSshTask(it) }
        stopSelf()
    }
    override fun onBind(intent: Intent?): IBinder? = null
    companion object {
        private const val CHANNEL = "tgproxy.helper.setup"
        internal const val NOTIFICATION_ID = 0x54470002
        internal const val WAKE_TIMEOUT_MS = 12 * 60 * 1000L
        internal const val EXTRA_RUN = "setup_run"
        internal const val ACTION_START = "io.github.byshadow64.tgproxy.HELPER_SETUP"
        internal const val ACTION_CANCEL = "io.github.byshadow64.tgproxy.CANCEL_HELPER_SETUP"
        fun start(context: Context, run: Long) {
            ContextCompat.startForegroundService(context, Intent(context, HelperSetupService::class.java).setAction(ACTION_START).putExtra(EXTRA_RUN, run))
        }
    }
}
