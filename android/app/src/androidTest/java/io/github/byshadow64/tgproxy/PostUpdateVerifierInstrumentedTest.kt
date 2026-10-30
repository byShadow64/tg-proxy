package io.github.byshadow64.tgproxy

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/** Read-only verification after a real installer upgrade; does not repair or delete evidence. */
@RunWith(AndroidJUnit4::class)
class PostUpdateVerifierInstrumentedTest {
    @Test fun exactProductionColdRestoreCleansUpdaterAndRetainsVersionFloor() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val arguments = InstrumentationRegistry.getArguments()
        assumeTrue("Explicit post-install verification only", arguments.getString("updatePostInstall") == "1")
        val expectedHash = arguments.getString("updateExpectedHash").orEmpty()
        assertTrue("POST_UPDATE_EXPECTED_HASH_REQUIRED", expectedHash.matches(Regex("[0-9a-f]{64}")))
        val context = instrumentation.targetContext
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        val code = if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else
            @Suppress("DEPRECATION") info.versionCode.toLong()
        assertEquals("POST_UPDATE_REQUIRES_CODE9", 9L, code)
        assertEquals("POST_UPDATE_REQUIRES_PRODUCTION_VERSION", "0.1.7-dev", info.versionName)
        val flags = context.applicationInfo.flags
        assertEquals("POST_UPDATE_DEBUG_OR_TEST_ONLY", 0,
            flags and (ApplicationInfo.FLAG_DEBUGGABLE or ApplicationInfo.FLAG_TEST_ONLY))
        val digest = MessageDigest.getInstance("SHA-256")
        File(context.applicationInfo.sourceDir).inputStream().use { input ->
            val buffer = ByteArray(65536)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count > 0) digest.update(buffer, 0, count)
            }
        }
        val installedHash = digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
        assertEquals("POST_UPDATE_APK_HASH_MISMATCH", expectedHash, installedHash)
        assertFalse("POST_UPDATE_REQUIRES_COLD_PROCESS", UpdateManager.isInitializedReady)
        // Do not launch MainActivity: foreground() could start a new network check and
        // hide the state produced by restoration alone. No preferences are changed here.
        UpdateManager.initialize(context)
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
        while ((!UpdateManager.isInitializedReady || UpdateManager.state.value.busy) &&
            System.nanoTime() < deadline) Thread.sleep(40)
        assertTrue("POST_UPDATE_RESTORE_TIMEOUT", UpdateManager.isInitializedReady && !UpdateManager.state.value.busy)

        val directory = File(context.noBackupFilesDir, "updates")
        assertTrue("POST_UPDATE_DIRECTORY_REQUIRED", directory.isDirectory)
        val entries = directory.listFiles()
        assertNotNull("POST_UPDATE_DIRECTORY_UNREADABLE", entries)
        val apkAbsent = !File(directory, "verified.apk").exists()
        val metadataAbsent = !File(directory, "manifest.json").exists()
        val partials = entries!!.count { it.name.startsWith("tg-update-") && it.name.endsWith(".part") }
        val ownSessions = context.packageManager.packageInstaller.mySessions.count { it.appPackageName == context.packageName }
        val preferences = context.getSharedPreferences("verified_updates", Context.MODE_PRIVATE)
        val highestCode = preferences.getLong("highest_code", -1)
        val highestHashMatches = preferences.getString("highest_hash", null) == expectedHash
        val savedSessionAbsent = !preferences.contains("session")
        val state = UpdateManager.state.value
        val receipt = JSONObject().put("api", Build.VERSION.SDK_INT).put("versionCode", code)
            .put("exactProductionApkHashMatched", true).put("privateFixture", false)
            .put("coldRestoreCompleted", true).put("phase", state.phase.name).put("busy", state.busy)
            .put("verifiedApkAbsent", apkAbsent).put("manifestAbsent", metadataAbsent)
            .put("partialFiles", partials).put("ownedInstallerSessions", ownSessions)
            .put("savedSessionAbsent", savedSessionAbsent).put("highestCode", highestCode)
            .put("highestHashMatched", highestHashMatches).put("profileCheckedSeparately", true)
        instrumentation.sendStatus(0, Bundle().apply {
            putString("tgproxy_receipt_name", "update-post-install")
            putString("tgproxy_receipt_json", receipt.toString())
        })
        assertTrue("POST_UPDATE_LEFT_VERIFIED_APK", apkAbsent)
        assertTrue("POST_UPDATE_LEFT_METADATA", metadataAbsent)
        assertEquals("POST_UPDATE_LEFT_PARTIALS", 0, partials)
        assertEquals("POST_UPDATE_LEFT_INSTALLER_SESSIONS", 0, ownSessions)
        assertTrue("POST_UPDATE_LEFT_SAVED_SESSION", savedSessionAbsent)
        assertEquals("POST_UPDATE_FLOOR_CHANGED", 9L, highestCode)
        assertTrue("POST_UPDATE_FLOOR_HASH_CHANGED", highestHashMatches)
        // The previous process's successful CURRENT state need not survive a restart:
        // with metadata already cleaned, IDLE truthfully means no channel check in
        // this process yet. Both must have no pending install or cached artifact.
        assertTrue("POST_UPDATE_PHASE_AFTER_RESTORE",
            state.phase == UpdatePhase.CURRENT || state.phase == UpdatePhase.IDLE)
    }
}
