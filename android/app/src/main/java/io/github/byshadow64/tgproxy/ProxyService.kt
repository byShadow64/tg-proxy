package io.github.byshadow64.tgproxy

import android.app.*
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import android.widget.RemoteViews
import androidx.core.app.NotificationCompat
import io.github.byshadow64.tgproxy.core.*
import io.github.byshadow64.tgproxy.ui.ProxyStatus
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

class ProxyService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val operations = Mutex()
    private val generation = AtomicInteger()
    private val engine = AtomicReference<ProxyEngine?>(null)
    private var ticker: Job? = null
    // onStartCommand and completion below run on Main. Ignored/duplicate commands
    // still advance Android's startId and must not keep an already stopped service alive.
    private var latestStartId = 0
    private val wakePolicy = NetworkWakePolicy(SystemClock::elapsedRealtime)
    private var networkWakeLock: PowerManager.WakeLock? = null
    private var wakeRenewedAt = 0L
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onCreate() {
        super.onCreate()
        AppRuntime.initialize(this)
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, getString(R.string.service_channel), NotificationManager.IMPORTANCE_LOW))
    }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        latestStartId = startId
        val action = intent?.action
        val reconnectSettings = if (action == ACTION_RECONNECT) AppRuntime.runningSettings() else null
        // Every foreground start must be promoted promptly, even if its queued
        // request became obsolete before Android delivered it to this service.
        if (action != ACTION_STOP) {
            try {
                val message = if (AppRuntime.state.value.status == ProxyStatus.RUNNING) R.string.service_notification else R.string.ui_status_starting
                if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIFICATION, notification(message), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
                else startForeground(NOTIFICATION, notification(message))
            } catch (_: Exception) { AppRuntime.failure(null); stopSelf(startId); return START_NOT_STICKY }
        }
        if (action !in setOf(ACTION_START, ACTION_RESTART, ACTION_RECONNECT, ACTION_STOP) ||
            (action != ACTION_STOP && !AppRuntime.canStart()) || (action == ACTION_RECONNECT && reconnectSettings == null)) {
            // Obsolete commands must not stop an earlier, still queued start.
            if (engine.get() == null && (generation.get() == 0 || AppRuntime.state.value.status !in setOf(ProxyStatus.STARTING, ProxyStatus.STOPPING))) {
                stopForeground(STOP_FOREGROUND_REMOVE); stopSelfResult(startId)
            }
            return START_NOT_STICKY
        }
        if (action == ACTION_START && engine.get() != null && AppRuntime.state.value.status == ProxyStatus.RUNNING) return START_NOT_STICKY
        val run = generation.incrementAndGet()
        if (action == ACTION_STOP) {
            AppRuntime.setStatus(ProxyStatus.STOPPING)
            val stopping = engine.get()
            scope.launch { stopping?.stop() }
            scope.launch { operations.withLock {
                if (run != generation.get()) return@withLock
                stopEngine()
                withContext(Dispatchers.Main.immediate) { if (run == generation.get()) {
                    AppRuntime.stopped()
                    AppRuntime.append(io.github.byshadow64.tgproxy.ui.LogLevel.INFO, getString(R.string.event_stopped))
                    stopForeground(STOP_FOREGROUND_REMOVE); stopSelfResult(latestStartId)
                } }
            } }
            return START_NOT_STICKY
        }
        AppRuntime.setStatus(ProxyStatus.STARTING)
        scope.launch { operations.withLock {
            try {
                if (run != generation.get()) return@withLock
                stopEngine()
                val settings = reconnectSettings ?: AppRuntime.settings()
                if (run != generation.get()) return@withLock
                val listener: (EngineEvent) -> Unit = { event -> if (run == generation.get()) {
                    if (event.code == EventCode.CONNECTION_OPENED) wakePolicy.connectionOpened(event.activeConnections)
                    if (event.code in setOf(EventCode.CONNECTION_OPENED, EventCode.CONNECTION_CLOSED))
                        updateWakeLock(nextStats = null, active = event.activeConnections, expectedRun = run)
                    AppRuntime.event(event)
                } }
                val provider = AppRuntime.helperConnectionProvider(settings)
                val next = if (provider == null) ProxyEngine(settings.engine(), listener) else ProxyEngine(settings.engine(), provider, listener)
                engine.set(next)
                next.start()
                val current = withContext(Dispatchers.Main.immediate) {
                    if (run != generation.get()) false else {
                        AppRuntime.running(settings)
                        try { getSystemService(NotificationManager::class.java).notify(NOTIFICATION, notification()) }
                        catch (_: SecurityException) { /* A revoked notification permission must not stop the listener. */ }
                        true
                    }
                }
                if (!current) { engine.compareAndSet(next, null); next.stop(); return@withLock }
                ticker?.cancel()
                ticker = scope.launch { while (isActive) {
                    val stats = next.snapshot()
                    updateWakeLock(stats, expectedRun = run)
                    withContext(Dispatchers.Main.immediate) {
                        if (run == generation.get() && engine.get() === next && AppRuntime.state.value.status == ProxyStatus.RUNNING) AppRuntime.metrics(stats)
                    }
                    delay(1000)
                } }
            } catch (e: Exception) {
                stopEngine()
                withContext(Dispatchers.Main.immediate) { if (run == generation.get()) {
                    AppRuntime.failure((e as? EngineException)?.code)
                    stopForeground(STOP_FOREGROUND_REMOVE); stopSelfResult(latestStartId)
                } }
            }
        } }
        return START_NOT_STICKY
    }
    private fun stopEngine() {
        val stopping = engine.getAndSet(null)
        ticker?.cancel(); ticker = null
        stopping?.stop()
        releaseNetworkWakeLock()
    }
    @Synchronized private fun updateWakeLock(nextStats: EngineStats?, active: Int = nextStats?.activeConnections ?: 0, expectedRun: Int) {
        if (generation.get() != expectedRun || engine.get() == null) return
        // Only payload progress renews the transfer window; keep-alives and a quiet listener do not.
        val stats = nextStats ?: engine.get()?.snapshot() ?: return
        if (!wakePolicy.update(active, stats.bytesUp, stats.bytesDown)) {
            networkWakeLock?.let { if (it.isHeld) it.release() }; return
        }
        val lock = networkWakeLock ?: getSystemService(PowerManager::class.java)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "TGProxy:ActiveNetwork").apply { setReferenceCounted(false) }
            .also { networkWakeLock = it }
        val now = SystemClock.elapsedRealtime()
        if (!lock.isHeld || now - wakeRenewedAt >= 30_000) {
            lock.acquire(NetworkWakePolicy.LOCK_TIMEOUT_MS); wakeRenewedAt = now
        }
    }
    @Synchronized private fun releaseNetworkWakeLock() {
        wakePolicy.reset()
        networkWakeLock?.let { if (it.isHeld) it.release() }; networkWakeLock = null; wakeRenewedAt = 0
    }
    private fun notification(message: Int = R.string.service_notification): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1, Intent(this, ProxyService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val compact = RemoteViews(packageName, R.layout.notification_proxy).apply {
            if (message != R.string.service_notification) setTextViewText(R.id.notification_title, getString(message))
            setTextViewText(R.id.notification_stop, getString(R.string.service_stop))
            setOnClickPendingIntent(R.id.notification_stop, stop)
            setOnClickPendingIntent(R.id.notification_open, open)
        }
        val expanded = compact.clone().apply {
            // The system supplies the standard Stop action in expanded view.
            setViewVisibility(R.id.notification_stop, android.view.View.GONE)
            setTextViewText(R.id.notification_title, getString(message))
        }
        return NotificationCompat.Builder(this, CHANNEL).setSmallIcon(R.drawable.ic_proxy_notification)
            .setContentTitle("TG Proxy").setContentText(getString(message))
            .setContentIntent(open).setOngoing(true).setSilent(true)
            .setColor(getColor(R.color.notification_action))
            .setStyle(NotificationCompat.DecoratedCustomViewStyle())
            .setCustomContentView(compact).setCustomBigContentView(expanded)
            .addAction(R.drawable.ic_proxy_notification, getString(R.string.service_stop), stop).build()
    }
    override fun onDestroy() {
        generation.incrementAndGet()
        stopEngine()
        if (AppRuntime.state.value.status != ProxyStatus.ERROR) AppRuntime.stopped()
        scope.cancel()
        super.onDestroy()
    }
    companion object {
        const val ACTION_START = "io.github.byshadow64.tgproxy.START"
        const val ACTION_RESTART = "io.github.byshadow64.tgproxy.RESTART"
        const val ACTION_RECONNECT = "io.github.byshadow64.tgproxy.RECONNECT"
        const val ACTION_STOP = "io.github.byshadow64.tgproxy.STOP"
        private const val CHANNEL = "tgproxy.connection"
        private const val NOTIFICATION = 1
    }
}
