package io.github.byshadow64.tgproxy

/** The system confirmation remains resumable in RAM until the session finishes. */
internal class InstallConfirmation<T> {
    private var value: T? = null
    private var automaticallyLaunched = false

    @Synchronized fun replace(next: T?) { value = next; automaticallyLaunched = false }

    @Synchronized fun forLaunch(automatic: Boolean): T? {
        val next = value ?: return null
        if (automatic && automaticallyLaunched) return null
        automaticallyLaunched = true
        return next
    }
}
