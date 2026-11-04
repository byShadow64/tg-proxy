package io.github.byshadow64.tgproxy

import org.junit.Assert.*
import org.junit.Test

class ServiceNetworkMonitorTest {
    private class Source : DefaultNetworkSource {
        var network: Any? = Any()
        var failSample = false
        var failRegistration = false
        var duringRegistration: ((DefaultNetworkSource.Listener) -> Unit)? = null
        val callbacks = mutableListOf<DefaultNetworkSource.Listener>()
        val removed = mutableListOf<DefaultNetworkSource.Listener>()
        override fun current(): Any? { check(!failSample); return network }
        override fun register(listener: DefaultNetworkSource.Listener) {
            callbacks += listener; duringRegistration?.invoke(listener); check(!failRegistration)
        }
        override fun unregister(listener: DefaultNetworkSource.Listener) { removed += listener }
        val callback get() = callbacks.last()
    }

    @Test fun startupAndRepeatedAvailabilityDoNotResetHealthySessions() {
        val source = Source()
        var changes = 0
        val monitor = ServiceNetworkMonitor(source) { changes++ }
        source.duringRegistration = { it.onAvailable(source.network!!) }
        repeat(5) { monitor.start() }
        repeat(5) { source.callback.onAvailable(source.network!!) }
        assertEquals(0, changes)
        assertEquals(1, source.callbacks.size)
    }

    @Test fun replacementResetsOnceAndLateLossOfOldNetworkIsIgnored() {
        val source = Source(); val old = source.network!!; val replacement = Any()
        var changes = 0
        ServiceNetworkMonitor(source) { changes++ }.start()
        source.callback.onAvailable(replacement)
        source.callback.onLost(old)
        source.callback.onAvailable(replacement)
        assertEquals(1, changes)
    }

    @Test fun lossThenReturnOfSameNetworkResetsBothTransitions() {
        val source = Source(); val old = source.network!!
        var changes = 0
        ServiceNetworkMonitor(source) { changes++ }.start()
        source.callback.onLost(old)
        source.callback.onLost(old)
        assertEquals(1, changes)
        source.callback.onAvailable(old)
        assertEquals(2, changes)
    }

    @Test fun initiallyOfflineSessionsAreRetiredWhenNetworkArrives() {
        val source = Source().apply { network = null }
        var changes = 0
        ServiceNetworkMonitor(source) { changes++ }.start()
        assertEquals(0, changes)
        source.callback.onAvailable(Any())
        assertEquals(1, changes)
    }

    @Test fun unknownBaselineDoesNotInventAnInitialTransition() {
        val source = Source().apply { failSample = true }
        var changes = 0
        ServiceNetworkMonitor(source) { changes++ }.start()
        val first = Any()
        source.callback.onLost(Any())
        source.callback.onAvailable(first)
        assertEquals(0, changes)
        source.callback.onLost(first)
        assertEquals(1, changes)
    }

    @Test fun stopAndPreviousRegistrationCannotResetANewRun() {
        val source = Source(); var changes = 0
        val monitor = ServiceNetworkMonitor(source) { changes++ }
        monitor.start(); val retired = source.callback
        monitor.stop(); monitor.stop()
        retired.onAvailable(Any()); retired.onLost(source.network!!)
        monitor.start()
        retired.onAvailable(Any()); retired.onLost(source.network!!)
        assertEquals(0, changes)
        assertEquals(1, source.removed.size)
        source.callback.onAvailable(Any())
        assertEquals(1, changes)
    }

    @Test fun registrationFailureRetiresPartialCallbacksAndCanBeRetried() {
        val source = Source().apply { failRegistration = true }; var changes = 0
        val monitor = ServiceNetworkMonitor(source) { changes++ }
        monitor.start()
        source.callback.onAvailable(Any())
        assertEquals(0, changes)
        assertEquals(1, source.removed.size)
        source.failRegistration = false
        monitor.start()
        source.callback.onAvailable(Any())
        assertEquals(1, changes)
    }
}
