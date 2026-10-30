package io.github.byshadow64.tgproxy

import android.app.NotificationManager
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import androidx.core.content.ContextCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Invalid/restarted intents only. No SSH endpoint, password, server mutation or proxy start. */
@RunWith(AndroidJUnit4::class)
class HelperSetupServiceInstrumentedTest {
    @Test fun setupServiceIsPrivateDataSyncAndCannotReconstructAnAbsentRamJob() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            val before = runBlocking { AppRuntime.settings() }
            @Suppress("DEPRECATION") val info = context.packageManager.getServiceInfo(
                android.content.ComponentName(context, HelperSetupService::class.java), PackageManager.GET_META_DATA)
            assertFalse(info.exported)
            if (Build.VERSION.SDK_INT >= 29) assertTrue(info.foregroundServiceType and ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC != 0)
            val request = Intent(context, HelperSetupService::class.java).setAction(HelperSetupService.ACTION_START)
                .putExtra(HelperSetupService.EXTRA_RUN, Long.MAX_VALUE)
            assertEquals(setOf(HelperSetupService.EXTRA_RUN), request.extras!!.keySet())
            val notifications = context.getSystemService(NotificationManager::class.java)
            for (invalid in listOf(request,
                Intent(context, HelperSetupService::class.java).setAction(HelperSetupService.ACTION_START),
                Intent(context, HelperSetupService::class.java).setAction("obsolete-internal-command"),
                Intent(context, HelperSetupService::class.java))) {
                scenario.onActivity { ContextCompat.startForegroundService(it, invalid) }
                Thread.sleep(300)
                fun isStopped(): Boolean {
                    @Suppress("DEPRECATION") val services = context.getSystemService(android.app.ActivityManager::class.java).getRunningServices(Int.MAX_VALUE)
                    return services.none { it.service.className == HelperSetupService::class.java.name } &&
                        notifications.activeNotifications.none { n -> n.id == HelperSetupService.NOTIFICATION_ID }
                }
                val end = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(3)
                while (!isStopped() && System.nanoTime() < end) Thread.sleep(25)
                assertTrue("A stale start must stop both service and notification", isStopped())
            }
            // A missing foreground acknowledgement is reported asynchronously by Android.
            Thread.sleep(6_000)
            val after = runBlocking { AppRuntime.settings() }
            assertEquals(before.secretHex, after.secretHex); assertEquals(before.ui(), after.ui())
            assertFalse(AppRuntime.state.value.isSaving)
        }
    }
}
