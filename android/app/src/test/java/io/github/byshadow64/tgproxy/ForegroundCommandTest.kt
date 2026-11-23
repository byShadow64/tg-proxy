package io.github.byshadow64.tgproxy

import org.junit.Assert.*
import org.junit.Test

class ForegroundCommandTest {
    @Test fun permissionResultWaitsForStartedActivityAndIsConsumedExactlyOnce() {
        val pending = PendingForegroundCommand()
        val command = ForegroundCommand.Start("start")
        assertTrue(pending.request(command))
        assertNull(pending.take(started = true))
        pending.permissionReturned()
        assertNull(pending.take(started = false))
        assertEquals(command, pending.take(started = true))
        assertNull(pending.take(started = true))
    }

    @Test fun repeatedRequestCannotReplaceTheCommandAwaitingPermission() {
        val pending = PendingForegroundCommand()
        val first = ForegroundCommand.ConnectHelper("192.0.2.10")
        assertTrue(pending.request(first))
        assertFalse(pending.request(ForegroundCommand.ProbeSsh("192.0.2.11", "22", "root")))
        pending.permissionReturned()
        assertEquals(first, pending.take(started = true))
        assertTrue(pending.request(ForegroundCommand.Start("start")))
        assertNull(pending.take(started = true))
    }
}
