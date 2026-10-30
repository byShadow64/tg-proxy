package io.github.byshadow64.tgproxy

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

@RunWith(AndroidJUnit4::class)
class SecureStoreInstrumentedTest {
    @Test fun androidKeystoreRoundTripPersistsOnlyCiphertextAndTamperFails() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val id = System.nanoTime().toString()
        val alias = "tgproxy.test.$id"; val prefsName = "tgproxy.test.$id"
        val prefs = context.getSharedPreferences(prefsName, 0)
        try {
            val s = AppSettings(1443, "01".repeat(16), true, "synthetic.example.invalid", 8444, "a1".repeat(32), "synthetic-test-token-".repeat(2))
            val store = SecureSettingsStore(context, alias, prefsName)
            assertNull(store.load()); store.save(s)
            assertNull(KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getKey(alias, null).encoded)
            assertEquals(s.ui(), SecureSettingsStore(context, alias, prefsName).load()!!.ui())
            val raw = prefs.all.toString()
            assertFalse(raw.contains(s.secretHex)); assertFalse(raw.contains(s.helperToken)); assertFalse(raw.contains(s.helperHost))
            prefs.edit().putString("encrypted_v1", "tampered-value").commit()
            try { store.load(); fail("Corrupt settings must not be reset or loaded") } catch (_: StoreException) { }
            assertEquals("tampered-value", prefs.getString("encrypted_v1", null))
        } finally {
            context.deleteSharedPreferences(prefsName)
            KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(alias) }
        }
    }
    @Test fun configurationBackupAndServiceExposureAreDisabled() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val app = context.applicationInfo
        assertEquals(0, app.flags and android.content.pm.ApplicationInfo.FLAG_ALLOW_BACKUP)
        val component = android.content.ComponentName(context, ProxyService::class.java)
        val service = context.packageManager.getServiceInfo(component, 0)
        assertFalse(service.exported)
        if (Build.VERSION.SDK_INT >= 34) {
            assertEquals(android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE, service.foregroundServiceType)
        }
    }
}
