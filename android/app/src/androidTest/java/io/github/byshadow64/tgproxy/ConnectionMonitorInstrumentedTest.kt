package io.github.byshadow64.tgproxy

import android.net.ConnectivityManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Observes the selected emulator's existing network; no probes, settings changes or proxy start. */
@RunWith(AndroidJUnit4::class)
class ConnectionMonitorInstrumentedTest {
    @Test fun platformLifecycleObservesPresenceAndRetiresItsCallbacks() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val monitor = ConnectionMonitor(context)
        assertEquals(ConnectionAvailability.UNKNOWN, monitor.state.value)
        try {
            repeat(5) {
                instrumentation.runOnMainSync { monitor.start(); monitor.start() }
                // This is a presence assertion, not a connectivity/Telegram reachability test.
                val expected = if (connectivity.activeNetwork == null) ConnectionAvailability.OFFLINE else ConnectionAvailability.AVAILABLE
                assertEquals(expected, monitor.state.value)
                instrumentation.runOnMainSync { monitor.stop(); monitor.stop() }
                assertEquals(ConnectionAvailability.UNKNOWN, monitor.state.value)
                instrumentation.waitForIdleSync()
                assertEquals(ConnectionAvailability.UNKNOWN, monitor.state.value)
            }
        } finally { instrumentation.runOnMainSync { monitor.stop() } }
    }
}
