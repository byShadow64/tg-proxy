package io.github.byshadow64.tgproxy

import org.junit.Assert.*
import org.junit.Test

class UpdatePolicyTest {
    @Test fun failedAutomaticAttemptHasCooldownButInitialCheckDoesNot() {
        val now = 10 * UpdatePolicy.DAY
        assertTrue(UpdatePolicy.automaticCheckDue(now, 0, 0))
        assertFalse(UpdatePolicy.automaticCheckDue(now + 1, 0, now))
        assertFalse(UpdatePolicy.automaticCheckDue(now + UpdatePolicy.RETRY - 1, 0, now))
        assertTrue(UpdatePolicy.automaticCheckDue(now + UpdatePolicy.RETRY, 0, now))
    }

    @Test fun successfulCheckWaitsADayRegardlessOfShorterRetryWindow() {
        val checked = 10 * UpdatePolicy.DAY
        assertFalse(UpdatePolicy.automaticCheckDue(checked + UpdatePolicy.RETRY, checked, checked))
        assertFalse(UpdatePolicy.automaticCheckDue(checked + UpdatePolicy.DAY - 1, checked, checked))
        assertTrue(UpdatePolicy.automaticCheckDue(checked + UpdatePolicy.DAY, checked, checked))
    }

    @Test fun clockCorrectionDoesNotSuppressChecksIndefinitely() {
        val beforeCorrection = 12 * UpdatePolicy.DAY
        val corrected = 10 * UpdatePolicy.DAY
        assertTrue(UpdatePolicy.automaticCheckDue(corrected, beforeCorrection, beforeCorrection))
        // Recording a new attempt at the corrected time immediately restores the cooldown.
        assertFalse(UpdatePolicy.automaticCheckDue(corrected + 1, beforeCorrection, corrected))
        assertEquals(0L, UpdatePolicy.retryDelay(corrected, beforeCorrection))
    }

    @Test fun pendingDownloadRetriesAreBoundedAndInitialDownloadIsImmediate() {
        val now = 10 * UpdatePolicy.DAY
        assertEquals(0L, UpdatePolicy.retryDelay(now, 0))
        assertEquals(UpdatePolicy.RETRY, UpdatePolicy.retryDelay(now, now))
        assertEquals(1L, UpdatePolicy.retryDelay(now + UpdatePolicy.RETRY - 1, now))
        assertEquals(0L, UpdatePolicy.retryDelay(now + UpdatePolicy.RETRY, now))
    }

    @Test fun rememberedHigherVersionCannotBeReplacedOrReplayedWithDifferentBytes() {
        val original = "a".repeat(64)
        val different = "b".repeat(64)
        assertTrue(UpdatePolicy.acceptsVersion(7, original, 0, null))
        assertTrue(UpdatePolicy.acceptsVersion(7, original, 7, original))
        assertFalse(UpdatePolicy.acceptsVersion(6, original, 7, original))
        assertFalse(UpdatePolicy.acceptsVersion(7, different, 7, original))
        assertFalse(UpdatePolicy.acceptsVersion(7, original, 7, null))
        assertTrue(UpdatePolicy.acceptsVersion(8, different, 7, original))
        assertFalse(UpdatePolicy.acceptsVersion(8, different, -1, null))
    }
}
