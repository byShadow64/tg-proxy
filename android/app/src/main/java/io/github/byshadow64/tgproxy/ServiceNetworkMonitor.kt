package io.github.byshadow64.tgproxy

import android.content.Context
import android.net.ConnectivityManager

/** Service-owned default-network changes, without probes or changing Android's network selection. */
internal class ServiceNetworkMonitor(
    private val source: DefaultNetworkSource,
    private val changed: () -> Unit,
) {
    constructor(context: Context, changed: () -> Unit) : this(AndroidDefaultNetworkSource(
        context.applicationContext.getSystemService(ConnectivityManager::class.java)), changed)

    private var registration: DefaultNetworkSource.Listener? = null
    private var known = false
    private var network: Any? = null

    @Synchronized fun start() {
        if (registration != null) return
        // Sampling before registration means its normal initial onAvailable callback
        // does not reset healthy sessions. A failed sample is only an unknown baseline.
        known = try { network = source.current(); true } catch (_: Exception) { network = null; false }
        val next = object : DefaultNetworkSource.Listener {
            override fun onAvailable(network: Any) = synchronized(this@ServiceNetworkMonitor) {
                if (registration !== this) return@synchronized
                val notify = known && this@ServiceNetworkMonitor.network != network
                known = true
                this@ServiceNetworkMonitor.network = network
                if (notify) changed()
            }

            override fun onLost(network: Any) = synchronized(this@ServiceNetworkMonitor) {
                if (registration !== this || !known || this@ServiceNetworkMonitor.network != network) return@synchronized
                this@ServiceNetworkMonitor.network = null
                changed()
            }
        }
        registration = next
        try { source.register(next) }
        catch (_: Exception) {
            registration = null; known = false; network = null
            runCatching { source.unregister(next) }
        }
    }

    @Synchronized fun stop() {
        val previous = registration
        registration = null; known = false; network = null
        if (previous != null) runCatching { source.unregister(previous) }
    }
}
