package io.github.byshadow64.tgproxy

import android.app.*
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.*

/** A single explicit enrollment, backed only by process RAM; no intent contains credentials. */
class HelperEnrollmentService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var activeRun: Long? = null
    private var waitingRun: Long? = null
    private var operation: Job? = null
    private var deadline: Job? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var latestStartId = 0
    private var destroyed = false

    override fun onCreate() {
        super.onCreate(); AppRuntime.initialize(this)
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, getString(R.string.enrollment_title), NotificationManager.IMPORTANCE_LOW))
    }
    @Synchronized override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        latestStartId = startId
        val run = intent?.getLongExtra(EXTRA_RUN, -1) ?: -1
        if (intent?.action == ACTION_CANCEL) {
            if (activeRun == run) AppRuntime.cancelEnrollment(run)
            else if (waitingRun == run) AppRuntime.abandonEnrollment(run)
            if (activeRun == null) stopSelfResult(startId)
            return START_NOT_STICKY
        }
        if (intent?.action != ACTION_START || run < 0) {
            if (activeRun == null) {
                // A restarted request cannot recover a lease, password or old cancellation flag.
                // Satisfy a possible startForegroundService request even when its intent is malformed.
                begin(-1)
            }
            return START_NOT_STICKY
        }
        if (activeRun == run || waitingRun == run) return START_NOT_STICKY
        if (activeRun != null) {
            if (!AppRuntime.hasQueuedEnrollment(run)) return START_NOT_STICKY
            waitingRun = run
            val previous = operation
            scope.launch {
                previous?.join()
                withContext(Dispatchers.Main) {
                    waitingRun = null
                    if (destroyed) AppRuntime.abandonEnrollment(run) else begin(run)
                }
            }
        } else begin(run) // Promote even a stale start before rejecting its absent RAM task.
        return START_NOT_STICKY
    }
    @Synchronized private fun begin(run: Long) {
        if (destroyed) { AppRuntime.abandonEnrollment(run); return }
        try {
            val notification = notification(run)
            if (Build.VERSION.SDK_INT >= 29) startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
            else startForeground(NOTIFICATION_ID, notification)
            wakeLock = getSystemService(PowerManager::class.java).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "TGProxy:HelperEnrollment").apply {
                setReferenceCounted(false); acquire(TIMEOUT_MS + 5_000)
            }
            val task = AppRuntime.takeEnrollment(run)
            if (task == null) { releaseWakeLock(); stopForeground(STOP_FOREGROUND_REMOVE); stopSelfResult(latestStartId); return }
            activeRun = run
            deadline = scope.launch { delay(TIMEOUT_MS); AppRuntime.cancelEnrollment(run) }
            operation = scope.launch { try { task() } finally { finish(run) } }
        } catch (_: Exception) {
            AppRuntime.abandonEnrollment(run)
            if (activeRun == run) finish(run) else { releaseWakeLock(); stopForeground(STOP_FOREGROUND_REMOVE); stopSelfResult(latestStartId) }
        }
    }
    @Synchronized private fun finish(run: Long) {
        if (activeRun != run) return
        activeRun = null; deadline?.cancel(); deadline = null
        releaseWakeLock()
        if (!destroyed) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            if (waitingRun == null) stopSelfResult(latestStartId)
        }
    }
    private fun notification(run: Long): Notification {
        val open = PendingIntent.getActivity(this, 3601, Intent(this, MainActivity::class.java), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val cancel = PendingIntent.getService(this, 3602, Intent(this, HelperEnrollmentService::class.java).setAction(ACTION_CANCEL).putExtra(EXTRA_RUN, run),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, CHANNEL).setSmallIcon(R.drawable.ic_proxy_notification)
            .setContentTitle(getString(R.string.enrollment_title)).setContentText(getString(R.string.enrollment_background))
            .setContentIntent(open).setOngoing(true).setSilent(true).setProgress(0, 0, true)
            .addAction(0, getString(R.string.ui_cancel), cancel).build()
    }
    private fun releaseWakeLock() { wakeLock?.let { if (it.isHeld) it.release() }; wakeLock = null }
    @Synchronized override fun onDestroy() {
        destroyed = true
        waitingRun?.let(AppRuntime::abandonEnrollment); waitingRun = null
        activeRun?.let { AppRuntime.cancelEnrollment(it); AppRuntime.abandonEnrollment(it) }
        deadline?.cancel(); scope.cancel(); releaseWakeLock()
        stopForeground(STOP_FOREGROUND_REMOVE); super.onDestroy()
    }
    override fun onTimeout(startId: Int, fgsType: Int) {
        activeRun?.let(AppRuntime::cancelEnrollment); stopSelf()
    }
    override fun onBind(intent: Intent?): IBinder? = null
    companion object {
        private const val CHANNEL = "tgproxy.helper.enrollment"
        internal const val NOTIFICATION_ID = 0x54470003
        internal const val TIMEOUT_MS = 90_000L
        internal const val EXTRA_RUN = "enrollment_run"
        internal const val ACTION_START = "io.github.byshadow64.tgproxy.HELPER_ENROLLMENT"
        internal const val ACTION_CANCEL = "io.github.byshadow64.tgproxy.CANCEL_HELPER_ENROLLMENT"
        fun start(context: Context, run: Long) = ContextCompat.startForegroundService(context,
            Intent(context, HelperEnrollmentService::class.java).setAction(ACTION_START).putExtra(EXTRA_RUN, run))
    }
}
