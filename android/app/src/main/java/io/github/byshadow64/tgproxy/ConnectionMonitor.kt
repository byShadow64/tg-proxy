package io.github.byshadow64.tgproxy

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.IdentityHashMap

/** Default-network presence only. AVAILABLE does not claim that Telegram or the internet is reachable. */
enum class ConnectionAvailability { UNKNOWN, AVAILABLE, OFFLINE }

/** The source has no network probes; tokens identify successive platform default networks. */
internal interface DefaultNetworkSource {
    interface Listener {
        fun onAvailable(network: Any)
        fun onLost(network: Any)
    }
    fun current(): Any?
    fun register(listener: Listener)
    fun unregister(listener: Listener)
}

/** Activity-owned observer; stopping the UI never stops the proxy or changes its routes. */
internal class ConnectionMonitor internal constructor(private val source: DefaultNetworkSource) {
    constructor(context: Context) : this(AndroidDefaultNetworkSource(
        context.applicationContext.getSystemService(ConnectivityManager::class.java)))

    private val mutable = MutableStateFlow(ConnectionAvailability.UNKNOWN)
    val state = mutable.asStateFlow()
    private var registration: DefaultNetworkSource.Listener? = null
    private var currentNetwork: Any? = null

    @Synchronized fun start() {
        if (registration != null) return
        var receivedEvent = false
        val next = object : DefaultNetworkSource.Listener {
            override fun onAvailable(network: Any) = synchronized(this@ConnectionMonitor) {
                if (registration !== this) return@synchronized
                receivedEvent = true
                currentNetwork = network
                mutable.value = ConnectionAvailability.AVAILABLE
            }

            override fun onLost(network: Any) = synchronized(this@ConnectionMonitor) {
                if (registration !== this) return@synchronized
                receivedEvent = true
                // Android can deliver the old network's loss after its replacement is available.
                if (currentNetwork != null && currentNetwork != network) return@synchronized
                // Do not query synchronous platform state from a callback: activeNetwork
                // may still name the network just lost. Wait for a replacement's callback.
                currentNetwork = null
                mutable.value = ConnectionAvailability.OFFLINE
            }
        }
        registration = next
        try {
            source.register(next)
        } catch (_: Exception) {
            registration = null
            currentNetwork = null
            mutable.value = ConnectionAvailability.UNKNOWN
            runCatching { source.unregister(next) }
            return
        }
        // A source may invoke a callback synchronously during registration. Its newer
        // observation must not be overwritten by a startup snapshot.
        if (!receivedEvent) sampleCurrent()
    }

    @Synchronized fun stop() {
        val previous = registration
        registration = null // Retire first; unregister can race an already queued callback.
        currentNetwork = null
        mutable.value = ConnectionAvailability.UNKNOWN
        if (previous != null) runCatching { source.unregister(previous) }
    }

    /** Initial snapshot only; callbacks use their ordered observations, without synchronous queries. */
    private fun sampleCurrent() {
        try {
            currentNetwork = source.current()
            mutable.value = if (currentNetwork == null) ConnectionAvailability.OFFLINE else ConnectionAvailability.AVAILABLE
        } catch (_: Exception) {
            currentNetwork = null
            mutable.value = ConnectionAvailability.UNKNOWN
        }
    }
}

private class AndroidDefaultNetworkSource(private val manager: ConnectivityManager) : DefaultNetworkSource {
    private val callbacks = IdentityHashMap<DefaultNetworkSource.Listener, ConnectivityManager.NetworkCallback>()
    override fun current(): Any? = manager.activeNetwork

    @Synchronized override fun register(listener: DefaultNetworkSource.Listener) {
        check(!callbacks.containsKey(listener))
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = listener.onAvailable(network)
            override fun onLost(network: Network) = listener.onLost(network)
        }
        callbacks[listener] = callback
        try { manager.registerDefaultNetworkCallback(callback) }
        catch (failure: Exception) {
            callbacks.remove(listener)
            runCatching { manager.unregisterNetworkCallback(callback) }
            throw failure
        }
    }

    @Synchronized override fun unregister(listener: DefaultNetworkSource.Listener) {
        val callback = callbacks.remove(listener) ?: return
        manager.unregisterNetworkCallback(callback)
    }
}
