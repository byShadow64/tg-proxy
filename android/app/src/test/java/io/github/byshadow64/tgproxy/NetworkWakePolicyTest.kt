package io.github.byshadow64.tgproxy

import org.junit.Assert.*
import org.junit.Test

class NetworkWakePolicyTest {
    @Test fun quietListenerAndExpiredQuietSocketNeverHoldCpuIndefinitely() {
        var now = 100L; val policy = NetworkWakePolicy { now }
        assertFalse(policy.update(0, 0, 0))
        policy.connectionOpened(1); assertTrue(policy.update(1, 0, 0))
        now += NetworkWakePolicy.SETUP_WINDOW_MS
        assertFalse(policy.update(1, 0, 0))
        repeat(100) { now += 1_000; assertFalse(policy.update(1, 0, 0)) }
    }
    @Test fun payloadProgressRenewsBoundedWindowAndStopClearsOldCounters() {
        var now = 1L; val policy = NetworkWakePolicy { now }
        policy.connectionOpened(1); assertTrue(policy.update(1, 64, 0))
        now += 59_000; assertTrue(policy.update(1, 64, 100))
        now += 59_000; assertTrue(policy.update(1, 64, 100))
        now += 1_000; assertFalse(policy.update(1, 64, 100))
        policy.connectionOpened(2); assertTrue(policy.update(2, 64, 100))
        assertFalse(policy.update(0, 64, 100))
        policy.reset(); assertFalse(policy.update(0, 0, 0))
        policy.connectionOpened(1); assertTrue(policy.update(1, 0, 0))
    }
}
