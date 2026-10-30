package io.github.byshadow64.tgproxy

import android.content.Intent
import android.content.Context
import android.app.ActivityManager
import android.os.Bundle
import androidx.core.content.ContextCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.byshadow64.tgproxy.ui.PairingStatus
import io.github.byshadow64.tgproxy.ui.ProxyStatus
import org.json.JSONObject
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Explicit owner-supplied runtime fixture. No endpoint, enrollment code or token is built into the APK. */
@RunWith(AndroidJUnit4::class)
class LivePairingRuntimeInstrumentedTest {
    @Suppress("DEPRECATION")
    private fun serviceExists(context: Context) = context.getSystemService(ActivityManager::class.java)
        .getRunningServices(Int.MAX_VALUE).any { it.service.className == ProxyService::class.java.name }
    private fun waitUntil(code: String, condition: () -> Boolean) {
        val deadline = System.nanoTime() + 45_000_000_000L
        while (System.nanoTime() < deadline) { if (condition()) return; Thread.sleep(50) }
        assertTrue(code, condition())
    }
    private fun hash(value: String) = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 255) }

    @Test fun ownerCodeEnrollsThroughAppRuntimeAndRestoresPreviousSettings() {
        val args = InstrumentationRegistry.getArguments()
        val ownerCode = args.getString("liveOwnerCode") ?: ""
        val registryHost = args.getString("liveRegistryHost") ?: ""
        val registered = registryHost.isNotBlank()
        val background = args.getString("liveBackground") == "1"
        var backgroundApplied = false
        val host = if (registered) registryHost else args.getString("liveHelperHost") ?: ""
        assumeTrue("Explicit runtime input required", registered || (ownerCode.isNotBlank() && host.isNotBlank()))
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val store = SecureSettingsStore(context)
        val prefs = context.getSharedPreferences("tgproxy.private.settings", 0)
        val before = store.load()
        assertTrue("LIVE_PAIRING_PREVIOUS_SETTINGS_REQUIRED", before != null)
        val originalCiphertext = prefs.getString("encrypted_v1", null)
        assertTrue("LIVE_PAIRING_PREVIOUS_CIPHERTEXT_REQUIRED", originalCiphertext != null)
        var paired = false
        var restored = false
        var realRoundTrip = false
        var listenerClosed = false
        var pairingStatus = "NOT_STARTED"
        var pairingReason = "NONE"
        var leaseNotPersisted = !registered
        var safeJournal = emptyList<String>()
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { it.stopService(Intent(it, ProxyService::class.java)) }
            waitUntil("LIVE_PAIRING_PROXY_STOP_TIMEOUT") {
                AppRuntime.state.value.hasSavedSettings && !AppRuntime.state.value.isSaving &&
                    AppRuntime.state.value.status == ProxyStatus.STOPPED && !serviceExists(context)
            }
            try {
                scenario.onActivity { if (registered) AppRuntime.connectHelperIp(host) else AppRuntime.pairHelper(host, ownerCode) }
                waitUntil("LIVE_PAIRING_ENROLLMENT_TIMEOUT") { !AppRuntime.state.value.isSaving && AppRuntime.state.value.pairingStatus != PairingStatus.CONNECTING }
                pairingStatus = AppRuntime.state.value.pairingStatus.name
                val message = AppRuntime.state.value.pairingMessage
                pairingReason = when (message) {
                    context.getString(R.string.service_pair_address) -> "INVALID_ADDRESS"
                    context.getString(R.string.service_pair_code) -> "INVALID_CODE"
                    context.getString(R.string.service_pair_timeout) -> "TIMEOUT"
                    context.getString(R.string.service_pair_cancelled) -> "CANCELLED"
                    context.getString(R.string.service_pair_failed) -> "UNVERIFIED_SERVER"
                    context.getString(R.string.service_store_error) -> "STORE_ERROR"
                    else -> "NONE"
                }
                assertTrue("LIVE_PAIRING_RUNTIME_NOT_SUCCESS", AppRuntime.state.value.pairingStatus == PairingStatus.SUCCESS)
                val saved = store.load()
                assertTrue("LIVE_PAIRING_STORE_MISSING", saved != null)
                assertTrue("LIVE_PAIRING_HELPER_DISABLED", saved!!.helperEnabled)
                assertTrue("LIVE_PAIRING_PIN_INCONSISTENT", saved.helperFingerprint == AppRuntime.state.value.settings.helperCertificateSha256)
                assertTrue("LIVE_PAIRING_TOKEN_INCONSISTENT", saved.helperToken == AppRuntime.state.value.settings.helperToken)
                if (registered) {
                    assertTrue("LIVE_REGISTRY_MODE_MISSING", saved.helperRegistryManaged)
                    assertTrue("LIVE_REGISTRY_BEARER_PERSISTED", saved.helperToken.isEmpty())
                    leaseNotPersisted = true
                }
                assertTrue("LIVE_PAIRING_LOCAL_IDENTITY_CHANGED", saved.secretHex == before!!.secretHex && saved.port == before.port)
                args.getString("expectedPinSha256")?.let { assertTrue("LIVE_PAIRING_PIN_MISMATCH", saved.helperFingerprint == it) }
                args.getString("expectedTokenSha256")?.let { assertTrue("LIVE_PAIRING_TOKEN_MISMATCH", hash(saved.helperToken) == it) }
                paired = true
                scenario.onActivity { ContextCompat.startForegroundService(it, Intent(it, ProxyService::class.java).setAction(ProxyService.ACTION_START)) }
                waitUntil("LIVE_HELPER_PROXY_START_TIMEOUT") { AppRuntime.state.value.status == ProxyStatus.RUNNING }
                if (background) {
                    android.os.ParcelFileDescriptor.AutoCloseInputStream(
                        InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand("input keyevent 3")
                    ).use { it.readBytes() }
                    waitUntil("LIVE_BACKGROUND_ACTIVITY_NOT_STOPPED") { scenario.state == androidx.lifecycle.Lifecycle.State.CREATED }
                    backgroundApplied = true
                }
                anonymousReqPq(saved.port, saved.secretHex)
                waitUntil("LIVE_HELPER_DATA_COUNTERS_MISSING") {
                    val metrics = AppRuntime.state.value.metrics
                    metrics.helperConnections > 0 && metrics.bytesSent > 0 && metrics.bytesReceived > 0
                }
                realRoundTrip = true
            } finally {
                if (backgroundApplied) {
                    android.os.ParcelFileDescriptor.AutoCloseInputStream(
                        InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(
                            "am start -W --activity-single-top -n ${context.packageName}/.MainActivity"
                        )
                    ).use { it.readBytes() }
                    waitUntil("LIVE_BACKGROUND_CLEANUP_ACTIVITY_NOT_RESUMED") { scenario.state == androidx.lifecycle.Lifecycle.State.RESUMED }
                }
                safeJournal = AppRuntime.state.value.journal.takeLast(12).map { it.message }
                if (serviceExists(context)) scenario.onActivity { it.startService(Intent(it, ProxyService::class.java).setAction(ProxyService.ACTION_STOP)) }
                waitUntil("LIVE_HELPER_PROXY_STOP_TIMEOUT") { AppRuntime.state.value.status == ProxyStatus.STOPPED && !serviceExists(context) }
                ServerSocket().use { socket -> socket.reuseAddress = true; socket.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), before!!.port)) }
                listenerClosed = true
                waitUntil("LIVE_PAIRING_RESTORE_BUSY_TIMEOUT") { !AppRuntime.state.value.isSaving }
                scenario.onActivity { AppRuntime.save(before!!.ui()) }
                waitUntil("LIVE_PAIRING_RESTORE_TIMEOUT") { !AppRuntime.state.value.isSaving && AppRuntime.state.value.settings == before!!.ui() }
                val loaded = store.load()
                assertTrue("LIVE_PAIRING_RESTORE_VALUES_CHANGED", loaded != null && loaded.secretHex == before!!.secretHex && loaded.ui() == before.ui())
                assertTrue("LIVE_PAIRING_RESTORE_CIPHERTEXT_FAILED", prefs.edit().putString("encrypted_v1", originalCiphertext).commit())
                restored = true
                val receipt = JSONObject()
                    .put("runtimeSuccess", paired && realRoundTrip && restored && listenerClosed)
                    .put("enrollmentVerified", paired).put("previousSettingsRestored", restored)
                    .put("actualHelperResPqMatched", realRoundTrip).put("helperDataCountersObserved", realRoundTrip)
                    .put("stoppedListenerClosed", listenerClosed)
                    .put("pairingStatus", pairingStatus).put("pairingReason", pairingReason)
                    .put("realOwnerCodeSuppliedAtRuntime", !registered).put("registeredDevicePublic", registered)
                    .put("leaseNeverPersisted", leaseNotPersisted)
                    .put("activityStoppedDuringRealData", backgroundApplied)
                    .put("safeJournal", org.json.JSONArray(safeJournal))
                    .put("credentialsLogged", false)
                File(context.filesDir, "live-pairing-result.json").writeText(receipt.toString(2))
                InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
                    putString("tgproxy_receipt_name", "live-pairing-result")
                    putString("tgproxy_receipt_json", receipt.toString())
                })
            }
        }
    }

    /** Independent anonymous MTProto client; never creates or sends account authorization. */
    internal fun anonymousReqPq(port: Int, secretHex: String, dc: Int = 2, media: Boolean = false) {
        val secret = secretHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val random = SecureRandom()
        try {
            Socket("127.0.0.1", port).use { client ->
                client.soTimeout = 15_000
                val init = ByteArray(64).also(random::nextBytes)
                init[0] = 0x11; init[4] = 1
                for (index in 56..59) init[index] = 0xdd.toByte()
                val dcWire = if (media) -dc else dc
                init[60] = dcWire.toByte(); init[61] = (dcWire shr 8).toByte()
                val up = ctr(sha(init.copyOfRange(8, 40) + secret), init.copyOfRange(40, 56))
                val encryptedInit = up.update(init)
                val wireInit = init.copyOf().also { encryptedInit.copyInto(it, 56, 56, 64) }
                val reversed = init.copyOfRange(8, 56).reversedArray()
                val down = ctr(sha(reversed.copyOfRange(0, 32) + secret), reversed.copyOfRange(32, 48))
                val nonce = ByteArray(16).also(random::nextBytes)
                val body = little(0xbe7e8ef1.toInt()) + nonce
                val now = System.currentTimeMillis()
                val messageId = ((now / 1000) shl 32) or ((((now % 1000) shl 32) / 1000) and -4L)
                val message = ByteArray(8) + ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(messageId).array() + little(body.size) + body
                client.getOutputStream().apply { write(wireInit); write(up.update(little(message.size) + message)); flush() }
                fun plain(size: Int) = down.update(client.getInputStream().exact(size))
                val size = ByteBuffer.wrap(plain(4)).order(ByteOrder.LITTLE_ENDIAN).int and 0x7fff_ffff
                assertTrue("LIVE_HELPER_REPLY_BOUNDS", size in 40..65536)
                val reply = plain(size)
                assertTrue("LIVE_HELPER_REPLY_AUTH_KEY", reply.copyOfRange(0, 8).contentEquals(ByteArray(8)))
                val bodySize = ByteBuffer.wrap(reply, 16, 4).order(ByteOrder.LITTLE_ENDIAN).int
                assertTrue("LIVE_HELPER_REPLY_BODY_BOUNDS", bodySize in 20..reply.size - 20)
                assertTrue("LIVE_HELPER_NOT_RES_PQ", ByteBuffer.wrap(reply, 20, 4).order(ByteOrder.LITTLE_ENDIAN).int == 0x05162463)
                assertTrue("LIVE_HELPER_REPLY_NONCE", reply.copyOfRange(24, 40).contentEquals(nonce))
            }
        } finally { secret.fill(0) }
    }
    private fun InputStream.exact(size: Int): ByteArray {
        val bytes = ByteArray(size); var offset = 0
        while (offset < size) { val count = read(bytes, offset, size - offset); check(count > 0); offset += count }
        return bytes
    }
    private fun sha(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
    private fun little(value: Int) = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array()
    private fun ctr(key: ByteArray, iv: ByteArray) = Cipher.getInstance("AES/CTR/NoPadding").apply {
        init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
    }
}
