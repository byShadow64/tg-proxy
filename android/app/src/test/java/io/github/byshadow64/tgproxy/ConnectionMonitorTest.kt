package io.github.byshadow64.tgproxy

import org.junit.Assert.*
import org.junit.Test

class ConnectionMonitorTest {
    private class Source : DefaultNetworkSource {
        var network: Any? = null
        var failSample = false
        var failRegistration = false
        var samples = 0
        var duringRegistration: ((DefaultNetworkSource.Listener) -> Unit)? = null
        val registrations = mutableListOf<DefaultNetworkSource.Listener>()
        val removals = mutableListOf<DefaultNetworkSource.Listener>()
        override fun current(): Any? {
            samples++
            check(!failSample)
            return network
        }
        override fun register(listener: DefaultNetworkSource.Listener) {
            registrations += listener
            duringRegistration?.invoke(listener)
            check(!failRegistration)
        }
        override fun unregister(listener: DefaultNetworkSource.Listener) { removals += listener }
        val callback get() = registrations.last()
    }

    @Test fun initialStateIsUnknownUntilObservationStarts() {
        val source = Source()
        val monitor = ConnectionMonitor(source)
        assertEquals(ConnectionAvailability.UNKNOWN, monitor.state.value)
        assertTrue(source.registrations.isEmpty())
        monitor.start()
        assertEquals(ConnectionAvailability.OFFLINE, monitor.state.value)
    }

    @Test fun startUsesExistingDefaultNetworkWithoutAProbe() {
        val source = Source().apply { network = Any() }
        val monitor = ConnectionMonitor(source)
        monitor.start()
        assertEquals(ConnectionAvailability.AVAILABLE, monitor.state.value)
        assertEquals(1, source.registrations.size)
    }

    @Test fun repeatedStartAndStopOwnOnlyOneRegistration() {
        val source = Source()
        val monitor = ConnectionMonitor(source)
        repeat(10) { monitor.start() }
        assertEquals(1, source.registrations.size)
        repeat(10) { monitor.stop() }
        assertEquals(1, source.removals.size)
        assertSame(source.registrations.single(), source.removals.single())
        assertEquals(ConnectionAvailability.UNKNOWN, monitor.state.value)
    }

    @Test fun lostOldNetworkDoesNotOverrideItsAvailableReplacement() {
        val first = Any(); val replacement = Any()
        val source = Source().apply { network = first }
        val monitor = ConnectionMonitor(source)
        monitor.start()
        source.callback.onAvailable(replacement)
        source.network = null // Even a lagging/unavailable snapshot cannot retire another known network.
        source.callback.onLost(first)
        assertEquals(ConnectionAvailability.AVAILABLE, monitor.state.value)
    }

    @Test fun replacementRemainsOfflineUntilItsAvailableCallbackArrives() {
        val first = Any(); val replacement = Any()
        val source = Source().apply { network = first }
        val monitor = ConnectionMonitor(source)
        monitor.start()
        source.network = replacement
        source.callback.onLost(first)
        assertEquals(ConnectionAvailability.OFFLINE, monitor.state.value)
        assertEquals(1, source.samples) // No synchronous query races a loss notification.
        source.callback.onAvailable(replacement)
        assertEquals(ConnectionAvailability.AVAILABLE, monitor.state.value)
        source.network = null
        source.callback.onLost(replacement)
        assertEquals(ConnectionAvailability.OFFLINE, monitor.state.value)
        assertEquals(1, source.samples)
    }

    @Test fun availableCallbackRecoversAnOfflineSnapshot() {
        val source = Source()
        val monitor = ConnectionMonitor(source)
        monitor.start()
        source.callback.onAvailable(Any())
        assertEquals(ConnectionAvailability.AVAILABLE, monitor.state.value)
    }

    @Test fun callbacksAfterStopAndFromAPreviousStartAreIgnored() {
        val old = Any()
        val source = Source().apply { network = old }
        val monitor = ConnectionMonitor(source)
        monitor.start()
        val retired = source.callback
        monitor.stop()
        retired.onAvailable(old)
        retired.onLost(old)
        assertEquals(ConnectionAvailability.UNKNOWN, monitor.state.value)
        source.network = null
        monitor.start()
        retired.onAvailable(old)
        retired.onLost(old)
        assertEquals(ConnectionAvailability.OFFLINE, monitor.state.value)
        source.callback.onAvailable(Any())
        assertEquals(ConnectionAvailability.AVAILABLE, monitor.state.value)
    }

    @Test fun registrationFailureRemainsUnknownAndRetiresAnyPartialCallback() {
        val source = Source().apply { network = Any(); failRegistration = true }
        val monitor = ConnectionMonitor(source)
        monitor.start()
        assertEquals(ConnectionAvailability.UNKNOWN, monitor.state.value)
        assertEquals(1, source.removals.size)
        source.callback.onAvailable(Any())
        assertEquals(ConnectionAvailability.UNKNOWN, monitor.state.value)
        source.failRegistration = false
        monitor.start()
        assertEquals(ConnectionAvailability.AVAILABLE, monitor.state.value)
    }

    @Test fun snapshotFailureRemainsUnknownAndLaterCallbackCanRecover() {
        val source = Source().apply { failSample = true }
        val monitor = ConnectionMonitor(source)
        monitor.start()
        assertEquals(ConnectionAvailability.UNKNOWN, monitor.state.value)
        source.callback.onAvailable(Any())
        assertEquals(ConnectionAvailability.AVAILABLE, monitor.state.value)
    }

    @Test fun laggingPlatformSnapshotCannotKeepALostNetworkAvailable() {
        val first = Any()
        val source = Source().apply { network = first }
        val monitor = ConnectionMonitor(source)
        monitor.start()
        // activeNetwork can still return the old network during its onLost callback.
        assertSame(first, source.network)
        source.callback.onLost(first)
        assertEquals(ConnectionAvailability.OFFLINE, monitor.state.value)
        assertEquals(1, source.samples)
    }

    @Test fun synchronousRegistrationCallbackWinsOverStartupSnapshot() {
        val source = Source().apply {
            network = null
            duringRegistration = { it.onAvailable(Any()) }
        }
        val monitor = ConnectionMonitor(source)
        monitor.start()
        assertEquals(ConnectionAvailability.AVAILABLE, monitor.state.value)
    }
}
