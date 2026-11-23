package io.github.byshadow64.tgproxy

import org.junit.Assert.*
import org.junit.Test

class InstallConfirmationTest {
    @Test fun automaticLaunchIsOnceButExplicitUserActionCanResumeConfirmation() {
        val pending = InstallConfirmation<Any>()
        val intent = Any()
        pending.replace(intent)
        assertSame(intent, pending.forLaunch(automatic = true))
        assertNull(pending.forLaunch(automatic = true))
        assertSame(intent, pending.forLaunch(automatic = false))
        assertNull(pending.forLaunch(automatic = true))
    }

    @Test fun terminalOutcomeClearsOldConfirmationAndNewSessionHasItsOwnLaunch() {
        val pending = InstallConfirmation<Any>()
        pending.replace(Any())
        assertNotNull(pending.forLaunch(automatic = false))
        pending.replace(null)
        assertNull(pending.forLaunch(automatic = false))
        val replacement = Any()
        pending.replace(replacement)
        assertSame(replacement, pending.forLaunch(automatic = true))
    }
}
