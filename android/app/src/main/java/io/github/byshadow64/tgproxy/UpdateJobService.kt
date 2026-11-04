package io.github.byshadow64.tgproxy

import android.app.job.JobParameters
import android.app.job.JobService
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Handler
import android.os.Looper
import java.util.concurrent.atomic.AtomicBoolean

class UpdateJobService : JobService() {
    private data class Active(val parameters: JobParameters, val cancelled: AtomicBoolean)
    private val active = mutableMapOf<Int, Active>()
    private val main = Handler(Looper.getMainLooper())

    override fun onStartJob(params: JobParameters): Boolean {
        val task = Active(params, AtomicBoolean(false))
        active.put(params.jobId, task)?.cancelled?.set(true)
        UpdateManager.initialize(this)
        UpdateManager.background(task.cancelled, params.jobId == UpdateManager.DOWNLOAD_JOB_ID) {
            main.post {
                // A stopped/replaced invocation must not finish another job with the same id.
                if (active[params.jobId] === task) {
                    active.remove(params.jobId)
                    // Keep the one-off job through JobScheduler's own completion protocol.
                    // Scheduling its replacement before this async completion can see the
                    // still-running job and silently lose a failed download's retry.
                    jobFinished(params, params.jobId == UpdateManager.DOWNLOAD_JOB_ID &&
                        UpdateManager.shouldRescheduleDownload())
                }
            }
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        // Binder delivers a new JobParameters instance for stop; jobId is its identity.
        val task = active.remove(params.jobId) ?: return false
        task.cancelled.set(true)
        return params.jobId == UpdateManager.DOWNLOAD_JOB_ID && UpdateManager.shouldRescheduleDownload()
    }

    override fun onDestroy() {
        active.values.forEach { it.cancelled.set(true) }
        active.clear()
        super.onDestroy()
    }
}

class UpdateInstallReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != context.packageName + ".UPDATE_RESULT") return
        val pending = goAsync()
        try {
            UpdateManager.initialize(context, intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -1))
            UpdateManager.installerResultWhenReady(Intent(intent)) { pending.finish() }
        } catch (_: Exception) { pending.finish() }
    }
}
