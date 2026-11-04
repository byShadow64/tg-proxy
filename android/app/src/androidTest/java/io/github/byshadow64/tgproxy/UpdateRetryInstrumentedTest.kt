package io.github.byshadow64.tgproxy

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.Context
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.byshadow64.tgproxy.core.AndroidUpdateManifest
import io.github.byshadow64.tgproxy.core.AndroidUpdateProtocol
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Real JobScheduler completion on an owned emulator. No network transfer or installation. */
@RunWith(AndroidJUnit4::class)
class UpdateRetryInstrumentedTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private fun shell(command: String): String = instrumentation.uiAutomation.executeShellCommand(command)
        .use { android.os.ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().use { input -> input.readText() } }
    private fun waitFor(predicate: () -> Boolean) {
        val end = System.nanoTime() + 15_000_000_000L
        while (!predicate() && System.nanoTime() < end) Thread.sleep(100)
        assertTrue("UPDATE_RETRY_TIMEOUT", predicate())
    }

    @Test fun completedOneOffDownloadRetainsNativeBackoffAndDisableCancelsIt() {
        assumeTrue(Build.HARDWARE in setOf("ranchu", "goldfish"))
        val context = instrumentation.targetContext
        val prefs = context.getSharedPreferences("verified_updates", Context.MODE_PRIVATE)
        UpdateManager.initialize(context)
        UpdateManager.cancel()
        val restored = UpdateManager::class.java.getDeclaredField("initializedReady").apply { isAccessible = true }
            .get(UpdateManager) as kotlinx.coroutines.Deferred<*>
        waitFor { restored.isCompleted && !UpdateManager.state.value.busy }
        val beforePreferences = prefs.all.toMap()
        val beforeState = UpdateManager.state.value
        val manifestField = UpdateManager::class.java.getDeclaredField("manifest").apply { isAccessible = true }
        val beforeManifest = manifestField.get(UpdateManager)
        val jobs = context.getSystemService(JobScheduler::class.java)
        try {
            UpdateManager.options(false, false)
            // A test-only in-memory pending-download sentinel. It never passes metadata
            // admission, reaches transport, touches the signed cache or advances the rollback floor.
            val constructor = AndroidUpdateManifest::class.java.declaredConstructors.single().apply { isAccessible = true }
            val pending = constructor.newInstance(Int.MAX_VALUE.toLong(), "99.0.0-dev", 26,
                "/android-dev/releases/2147483647/${"a".repeat(64)}.apk", 1L, "a".repeat(64),
                AndroidUpdateProtocol.ORIGINAL_SIGNER_SHA256, "Test", "Test", 1L, byteArrayOf())
            manifestField.set(UpdateManager, pending)
            assertTrue(prefs.edit().putLong("download_attempt", System.currentTimeMillis()).commit())
            UpdateManager.options(true, true)
            waitFor { jobs.getPendingJob(UpdateManager.DOWNLOAD_JOB_ID) != null }
            // Force only this app's own cooldown job. background() has no eligible transfer,
            // and must finish with wantsReschedule=true instead of losing the one-off job.
            val result = shell("cmd jobscheduler run -f ${context.packageName} ${UpdateManager.DOWNLOAD_JOB_ID}")
            assertTrue("JOB_FORCE_FAILED", result.contains("Running job"))
            waitFor {
                val dump = shell("dumpsys jobscheduler")
                val section = dump.substringAfter("/${UpdateManager.DOWNLOAD_JOB_ID}: ", "").substringBefore("\n  JOB #")
                section.contains(Regex("Num failures: [1-9]"))
            }
            val retried = jobs.getPendingJob(UpdateManager.DOWNLOAD_JOB_ID)
            assertNotNull("FAILED_DOWNLOAD_LOST_RETRY", retried)
            assertEquals(JobInfo.NETWORK_TYPE_UNMETERED, retried!!.networkType)
            assertTrue(retried.isRequireBatteryNotLow)
            assertEquals(UpdatePolicy.RETRY, retried.initialBackoffMillis)
            assertEquals(JobInfo.BACKOFF_POLICY_LINEAR, retried.backoffPolicy)
            assertTrue(retried.isPersisted)
            UpdateManager.options(false, false)
            assertNull(jobs.getPendingJob(UpdateManager.DOWNLOAD_JOB_ID))
        } finally {
            UpdateManager.options(false, false)
            manifestField.set(UpdateManager, beforeManifest)
            @Suppress("UNCHECKED_CAST")
            (UpdateManager::class.java.getDeclaredField("mutable").apply { isAccessible = true }
                .get(UpdateManager) as kotlinx.coroutines.flow.MutableStateFlow<UpdateUiState>).value = beforeState
            val editor = prefs.edit().clear()
            beforePreferences.forEach { (key, value) -> when (value) {
                is String -> editor.putString(key, value)
                is Boolean -> editor.putBoolean(key, value)
                is Int -> editor.putInt(key, value)
                is Long -> editor.putLong(key, value)
                is Float -> editor.putFloat(key, value)
                is Set<*> -> @Suppress("UNCHECKED_CAST") editor.putStringSet(key, value as Set<String>)
            } }
            assertTrue(editor.commit())
            UpdateManager.options(beforeState.automatic, beforeState.wifiDownload)
        }
    }
}
