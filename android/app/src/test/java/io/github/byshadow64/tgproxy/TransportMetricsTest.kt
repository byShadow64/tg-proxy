package io.github.byshadow64.tgproxy

import io.github.byshadow64.tgproxy.core.EngineState
import io.github.byshadow64.tgproxy.core.EngineStats
import org.junit.Assert.assertEquals
import org.junit.Test

/** The existing WSS UI counter includes both official and relay WebSockets, separately from Helper. */
class TransportMetricsTest {
    private fun report(direct: Long, relay: Long, helper: Long) {
        AppRuntime.metrics(EngineStats(EngineState.RUNNING, 1443, activeConnections = 3,
            bytesUp = 17, bytesDown = 23, directConnections = direct, helperConnections = helper, relayConnections = relay))
    }
    @Test fun allRelayConnectionsAreCountedAsWss() {
        report(0, 7, 0)
        assertEquals(7L, AppRuntime.state.value.metrics.directConnections)
        assertEquals(0L, AppRuntime.state.value.metrics.helperConnections)
    }
    @Test fun officialAndRelayConnectionsShareExistingWssCounter() {
        report(2, 5, 3)
        val metrics = AppRuntime.state.value.metrics
        assertEquals(7L, metrics.directConnections); assertEquals(3L, metrics.helperConnections)
        assertEquals(3, metrics.activeConnections); assertEquals(17L, metrics.bytesSent); assertEquals(23L, metrics.bytesReceived)
    }
    @Test fun helperConnectionsRemainSeparateFromWss() {
        report(0, 0, 9)
        assertEquals(0L, AppRuntime.state.value.metrics.directConnections)
        assertEquals(9L, AppRuntime.state.value.metrics.helperConnections)
    }
}
