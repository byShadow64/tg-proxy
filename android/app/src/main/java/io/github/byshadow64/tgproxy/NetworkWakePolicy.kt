package io.github.byshadow64.tgproxy

/** A quiet listener or idle socket does not keep the CPU awake for the whole foreground session. */
internal class NetworkWakePolicy(private val nowMs: () -> Long) {
    private var active = 0
    private var up = 0L
    private var down = 0L
    private var until = 0L

    @Synchronized fun connectionOpened(count: Int) {
        active = count
        until = maxOf(until, nowMs() + SETUP_WINDOW_MS)
    }
    @Synchronized fun update(count: Int, bytesUp: Long, bytesDown: Long): Boolean {
        val now = nowMs()
        if (bytesUp > up || bytesDown > down) until = now + TRANSFER_WINDOW_MS
        active = count; up = bytesUp; down = bytesDown
        if (active == 0) until = 0
        return active > 0 && now < until
    }
    @Synchronized fun reset() { active = 0; up = 0; down = 0; until = 0 }
    companion object {
        internal const val SETUP_WINDOW_MS = 45_000L
        internal const val TRANSFER_WINDOW_MS = 60_000L
        internal const val LOCK_TIMEOUT_MS = 65_000L
    }
}
