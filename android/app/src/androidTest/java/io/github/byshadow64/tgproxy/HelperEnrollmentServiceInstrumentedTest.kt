package io.github.byshadow64.tgproxy

import android.Manifest
import android.app.ActivityManager
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.byshadow64.tgproxy.core.*
import io.github.byshadow64.tgproxy.ui.PairingStatus
import io.github.byshadow64.tgproxy.ui.ProxyStatus
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** Only an in-process signed registry fixture. No HTTP, real Helper, SSH password or account. */
@RunWith(AndroidJUnit4::class)
class HelperEnrollmentServiceInstrumentedTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private fun waitFor(code: String, predicate: () -> Boolean) {
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(12)
        while (System.nanoTime() < until) { if (predicate()) return; Thread.sleep(25) }
        assertTrue(code, predicate())
    }
    @Suppress("DEPRECATION") private fun serviceExists() = context.getSystemService(ActivityManager::class.java)
        .getRunningServices(Int.MAX_VALUE).any { it.service.className == HelperEnrollmentService::class.java.name }
    private fun notification() = context.getSystemService(NotificationManager::class.java).activeNotifications
        .singleOrNull { it.id == HelperEnrollmentService.NOTIFICATION_ID }?.notification
    private fun home(scenario: ActivityScenario<MainActivity>) {
        android.os.ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand("input keyevent 3")).use { it.readBytes() }
        waitFor("HOME_ACTIVITY_STOPPED") { scenario.state == Lifecycle.State.CREATED }
    }
    private fun foreground(scenario: ActivityScenario<MainActivity>) {
        android.os.ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(
            "am start -n ${context.packageName}/.MainActivity")).use { it.readBytes() }
        waitFor("EXPLICIT_REOPEN_RESUMED") { scenario.state == Lifecycle.State.RESUMED }
    }
    private fun withRegistry(test: (ActivityScenario<MainActivity>, SignedRegistry) -> Unit) {
        if (Build.VERSION.SDK_INT >= 33) instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            waitFor("RUNTIME_READY") { AppRuntime.state.value.hasSavedSettings && !AppRuntime.state.value.isSaving && AppRuntime.state.value.status == ProxyStatus.STOPPED }
            val before = runBlocking { AppRuntime.settings() }
            val preferences = context.getSharedPreferences("tgproxy.private.settings", 0)
            val ciphertext = preferences.getString("encrypted_v1", null)
            val field = AppRuntime::class.java.getDeclaredField("registry").apply { isAccessible = true }
            val previousClient = field.get(AppRuntime)
            val registry = SignedRegistry()
            field.set(AppRuntime, registry.client)
            try { test(scenario, registry) }
            finally {
                registry.release.countDown(); AppRuntime.cancelHelperConnect()
                context.stopService(Intent(context, HelperEnrollmentService::class.java))
                waitFor("ENROLLMENT_CLEANUP") { !AppRuntime.state.value.isSaving && !serviceExists() }
                field.set(AppRuntime, previousClient)
                foreground(scenario)
                scenario.onActivity { AppRuntime.save(before.ui()) }
                waitFor("EXACT_SETTINGS_RESTORED") { !AppRuntime.state.value.isSaving && AppRuntime.state.value.settings == before.ui() }
                assertTrue(preferences.edit().putString("encrypted_v1", ciphertext).commit())
            }
        }
    }
    @Test fun enrollmentSurvivesHomeAndProviderRefreshesExpiredLeaseWithoutPersistingBearer() = withRegistry { scenario, registry ->
        scenario.onActivity { AppRuntime.connectHelperIp(SignedRegistry.IP) }
        assertTrue(registry.entered.await(5, TimeUnit.SECONDS))
        waitFor("ENROLLMENT_FOREGROUND") { notification() != null && serviceExists() }
        assertTrue(notification()!!.flags and android.app.Notification.FLAG_FOREGROUND_SERVICE != 0)
        home(scenario)
        Thread.sleep(300)
        assertTrue(AppRuntime.state.value.isSaving); assertTrue(serviceExists())
        registry.release.countDown()
        waitFor("BACKGROUND_ENROLLMENT_SUCCESS") { !AppRuntime.state.value.isSaving && AppRuntime.state.value.pairingStatus == PairingStatus.SUCCESS && !serviceExists() }
        val saved = runBlocking { AppRuntime.settings() }
        assertTrue(saved.helperRegistryManaged); assertEquals("", saved.helperToken)
        val provider = AppRuntime.helperConnectionProvider(saved)!!
        val first = provider.settings { false }
        registry.clock.addAndGet(571)
        val second = provider.settings { false }
        assertFalse(first.token == second.token)
        assertEquals(2, registry.issued.get())
        val journalId = AppRuntime.state.value.journal.lastOrNull()?.id ?: 0L
        try { provider.settings { true }; fail("Cancelled session must not receive a lease") }
        catch (failure: RegistryException) { assertEquals(RegistryFailureCode.CANCELLED, failure.code) }
        assertTrue("A session closing must not be reported as a user cancelling enrollment",
            AppRuntime.state.value.journal.none { it.id > journalId && it.message == context.getString(R.string.service_registry_cancelled) })
        val persisted = SecureSettingsStore(context).load()!!
        assertEquals("", persisted.helperToken)
        assertEquals(saved.secretHex, persisted.secretHex)
        assertEquals(Lifecycle.State.CREATED, scenario.state)
    }
    @Test fun notificationCancelAfterHomeStopsEnrollmentAndRetryUsesFreshCancellation() = withRegistry { scenario, registry ->
        val preferences = context.getSharedPreferences("tgproxy.private.settings", 0)
        val before = preferences.getString("encrypted_v1", null)
        scenario.onActivity { AppRuntime.connectHelperIp(SignedRegistry.IP) }
        assertTrue(registry.entered.await(5, TimeUnit.SECONDS))
        waitFor("ENROLLMENT_CANCEL_READY") { notification()?.actions?.isNotEmpty() == true }
        home(scenario)
        notification()!!.actions.single().actionIntent.send()
        waitFor("NOTIFICATION_CANCEL_STOPS_SERVICE") { !AppRuntime.state.value.isSaving && !serviceExists() && notification() == null }
        assertEquals(PairingStatus.ERROR, AppRuntime.state.value.pairingStatus)
        assertEquals(context.getString(R.string.service_registry_cancelled), AppRuntime.state.value.pairingMessage)
        assertEquals(before, preferences.getString("encrypted_v1", null))
        registry.release.countDown(); foreground(scenario)
        scenario.onActivity { AppRuntime.connectHelperIp(SignedRegistry.IP) }
        waitFor("FRESH_RETRY_SUCCEEDS") { !AppRuntime.state.value.isSaving && AppRuntime.state.value.pairingStatus == PairingStatus.SUCCESS && !serviceExists() }
    }
    @Test fun immediateCancelBeforeServiceClaimDoesNotIssueLeaseOrOverwriteProfile() = withRegistry { scenario, registry ->
        val preferences = context.getSharedPreferences("tgproxy.private.settings", 0)
        val before = preferences.getString("encrypted_v1", null)
        scenario.onActivity { AppRuntime.connectHelperIp(SignedRegistry.IP); AppRuntime.cancelHelperConnect() }
        waitFor("EARLY_CANCEL_FINISHED") { !AppRuntime.state.value.isSaving && !serviceExists() }
        assertEquals(0, registry.issued.get()); assertEquals(1L, registry.entered.count)
        assertEquals(before, preferences.getString("encrypted_v1", null))
    }
    @Test fun absentRamJobCannotBeReconstructedByRestartedOrStaleIntent() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            waitFor("RUNTIME_READY") { AppRuntime.state.value.hasSavedSettings && !AppRuntime.state.value.isSaving }
            @Suppress("DEPRECATION") val info = context.packageManager.getServiceInfo(
                android.content.ComponentName(context, HelperEnrollmentService::class.java), PackageManager.GET_META_DATA)
            assertFalse(info.exported)
            if (Build.VERSION.SDK_INT >= 29) assertTrue(info.foregroundServiceType and ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC != 0)
            val before = context.getSharedPreferences("tgproxy.private.settings", 0).getString("encrypted_v1", null)
            for (request in listOf(
                Intent(context, HelperEnrollmentService::class.java).setAction(HelperEnrollmentService.ACTION_START).putExtra(HelperEnrollmentService.EXTRA_RUN, Long.MAX_VALUE),
                Intent(context, HelperEnrollmentService::class.java).setAction(HelperEnrollmentService.ACTION_START),
                Intent(context, HelperEnrollmentService::class.java).setAction("invalid"),
                Intent(context, HelperEnrollmentService::class.java),
            )) {
                scenario.onActivity { ContextCompat.startForegroundService(it, request) }
                Thread.sleep(300)
                waitFor("ABSENT_RAM_JOB_NOT_RESTARTED") { !serviceExists() && notification() == null }
            }
            assertFalse(AppRuntime.state.value.isSaving)
            assertEquals(before, context.getSharedPreferences("tgproxy.private.settings", 0).getString("encrypted_v1", null))
        }
    }

    private class SignedRegistry : RegistryTransport {
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val issued = AtomicInteger(); val clock = AtomicLong(System.currentTimeMillis() / 1000)
        private val signer = pair(); private val installation = pair()
        private val identity = object : RegistryDeviceIdentity {
            override fun publicKeySpki() = installation.public.encoded
            override fun sign(message: ByteArray) = sign(installation.private, message)
        }
        val client = HelperRegistryClient(this, signer.public.encoded, identity, clockSeconds = clock::get)
        private var challenge = 0
        override fun post(path: String, body: ByteArray, cancelled: () -> Boolean): ByteArray {
            if (cancelled()) throw RegistryException(RegistryFailureCode.CANCELLED)
            return when (path) {
                "/v1/challenge" -> canonical(mapOf("v" to 1, "challenge" to encode(ByteArray(32) { (++challenge + it).toByte() }), "expires_at" to clock.get() + 60))
                "/v1/register" -> canonical(mapOf("v" to 1, "device_id" to hex(MessageDigest.getInstance("SHA-256").digest(installation.public.encoded)), "access" to "registered-device-public"))
                "/v1/lease" -> {
                    entered.countDown()
                    while (!release.await(10, TimeUnit.MILLISECONDS)) if (cancelled()) throw RegistryException(RegistryFailureCode.CANCELLED)
                    if (cancelled()) throw RegistryException(RegistryFailureCode.CANCELLED)
                    val serial = issued.incrementAndGet(); val now = clock.get()
                    val helper = ByteArray(16) { 17 }; val pin = ByteArray(32) { 34 }
                    val payload = canonical(mapOf("v" to 1, "helper_id" to encode(helper), "ip" to IP, "port" to 8444,
                        "fingerprint" to hex(pin), "iat" to now, "exp" to now + 600, "protocol" to "helper-v2-lease", "access" to "registered-device-public"))
                    val tokenBytes = ByteBuffer.allocate(113).put(1).put(helper).put(MessageDigest.getInstance("SHA-256").digest(installation.public.encoded))
                        .put(pin).putLong(now).putLong(now + 600).put(ByteArray(16) { serial.toByte() }).array()
                    canonical(mapOf("v" to 1, "descriptor" to mapOf("v" to 1, "payload" to encode(payload), "signature" to encode(sign(signer.private, "TGPROXY_REGISTRY_DESCRIPTOR_V1\u0000".toByteArray() + payload))),
                        "token" to "TGL1.${encode(tokenBytes)}.${encode(sign(signer.private, "TGPROXY_REGISTRY_LEASE_V1\u0000".toByteArray() + tokenBytes))}"))
                }
                else -> error("UNEXPECTED_LOCAL_FIXTURE_PATH")
            }
        }
        companion object {
            const val IP = "192.0.2.10"
            private fun pair() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            private fun sign(key: java.security.PrivateKey, data: ByteArray) = Signature.getInstance("SHA256withECDSA").run { initSign(key); update(data); sign() }
            private fun encode(data: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(data)
            private fun hex(data: ByteArray) = data.joinToString("") { "%02x".format(it.toInt() and 255) }
            private fun canonical(values: Map<String, Any>): ByteArray {
                fun obj(map: Map<String, Any>): String = map.toSortedMap().entries.joinToString(",", "{", "}") { (key, value) ->
                    JSONObject.quote(key) + ":" + when (value) {
                        is String -> JSONObject.quote(value)
                        is Map<*, *> -> { @Suppress("UNCHECKED_CAST") obj(value as Map<String, Any>) }
                        else -> value.toString()
                    }
                }
                return obj(values).toByteArray(Charsets.US_ASCII)
            }
        }
    }
}
