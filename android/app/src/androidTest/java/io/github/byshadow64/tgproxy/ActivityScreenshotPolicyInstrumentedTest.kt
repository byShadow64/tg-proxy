package io.github.byshadow64.tgproxy

import android.content.res.Configuration
import android.view.WindowManager
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Locale

/** User explicitly permits production screenshots. This check captures no credential editor. */
@RunWith(AndroidJUnit4::class)
class ActivityScreenshotPolicyInstrumentedTest {
    @Test fun actualActivityAllowsScreenshotsAndDevelopmentNoticeIsLocalized() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { assertEquals(0, it.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE) }
        }
        fun localized(tag: String) = context.createConfigurationContext(Configuration(context.resources.configuration).apply {
            setLocale(Locale.forLanguageTag(tag))
        }).getString(R.string.ui_dev_disclaimer)
        assertEquals("Dev-версия — не отражает финального качества", localized("ru"))
        assertEquals("Dev version — does not reflect final quality", localized("en"))
    }
}
