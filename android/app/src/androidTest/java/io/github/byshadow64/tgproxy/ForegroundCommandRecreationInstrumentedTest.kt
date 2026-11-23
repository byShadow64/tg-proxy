package io.github.byshadow64.tgproxy

import androidx.lifecycle.ViewModelProvider
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** No permission grant, service start, SSH operation or credential input is performed. */
@RunWith(AndroidJUnit4::class)
class ForegroundCommandRecreationInstrumentedTest {
    @Test fun pendingPublicCommandSurvivesActivityRecreationWithoutSavedState() {
        val command = ForegroundCommand.ProbeSsh("192.0.2.10", "22", "root")
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            var retained: ForegroundCommandViewModel? = null
            scenario.onActivity { activity ->
                retained = ViewModelProvider(activity)[ForegroundCommandViewModel::class.java]
                assertTrue(retained!!.pending.request(command))
            }
            scenario.recreate()
            scenario.onActivity { activity ->
                val current = ViewModelProvider(activity)[ForegroundCommandViewModel::class.java]
                assertSame(retained, current)
                assertNull(current.pending.take(started = true))
                current.pending.permissionReturned()
                assertEquals(command, current.pending.take(started = true))
                assertNull(current.pending.take(started = true))
            }
        }
    }
}
