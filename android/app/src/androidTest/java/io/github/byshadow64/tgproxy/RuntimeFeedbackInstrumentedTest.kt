package io.github.byshadow64.tgproxy

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.byshadow64.tgproxy.ui.ProxyStatus
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** In-memory feedback acknowledgement must never change the saved proxy or its failure. */
@RunWith(AndroidJUnit4::class)
class RuntimeFeedbackInstrumentedTest {
    @Test fun repeatedMessagesUseNewIdsAndOldAcknowledgementCannotClearNewFeedback() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        AppRuntime.initialize(context)
        val deadline = System.nanoTime() + 10_000_000_000L
        while (!AppRuntime.state.value.hasSavedSettings && System.nanoTime() < deadline) Thread.sleep(20)
        assertTrue(AppRuntime.state.value.hasSavedSettings)
        val before = AppRuntime.state.value
        try {
            AppRuntime.setStatus(ProxyStatus.ERROR, "ORIGINAL_STARTUP_FAILURE")
            AppRuntime.showMessage(R.string.service_report_copied)
            val first = AppRuntime.state.value.feedback!!
            AppRuntime.showMessage(R.string.service_report_copied)
            val second = AppRuntime.state.value.feedback!!
            assertTrue(second.id > first.id)
            assertEquals(first.message, second.message)
            AppRuntime.consumeFeedback(first.id)
            assertEquals(second, AppRuntime.state.value.feedback)
            assertEquals(ProxyStatus.ERROR, AppRuntime.state.value.status)
            assertEquals("ORIGINAL_STARTUP_FAILURE", AppRuntime.state.value.statusMessage)
            assertEquals(before.settings, AppRuntime.state.value.settings)
            AppRuntime.consumeFeedback(second.id)
            assertNull(AppRuntime.state.value.feedback)
        } finally {
            AppRuntime.state.value.feedback?.let { AppRuntime.consumeFeedback(it.id) }
            AppRuntime.setStatus(before.status, before.statusMessage)
        }
    }
}
