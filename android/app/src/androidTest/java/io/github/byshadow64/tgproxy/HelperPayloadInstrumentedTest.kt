package io.github.byshadow64.tgproxy

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Exercise the real APK's bounded/hash-checked SSH assets rather than a host fixture. */
@RunWith(AndroidJUnit4::class)
class HelperPayloadInstrumentedTest {
    @Test fun embeddedPublicHelperIncludesTelegramPolicyAndCurrentProject() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val files = HelperPayloadAssets.load(context.assets)
        assertEquals(27, files.size)
        assertTrue(files.any { it.path == "proxy/route_policy.py" && it.size > 0 })
        val project = context.assets.open("helper-payload/proxy/project.py").bufferedReader().use { it.readText() }
        val service = context.assets.open("helper-payload/tg-helper.service").bufferedReader().use { it.readText() }
        assertTrue(project.contains("REPOSITORY = \"byShadow64/tg-proxy\""))
        assertTrue(service.contains("https://github.com/byShadow64/tg-proxy/blob/main/docs/RU/Helper.md"))
    }
}
