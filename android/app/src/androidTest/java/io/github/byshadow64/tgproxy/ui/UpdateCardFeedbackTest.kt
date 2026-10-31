package io.github.byshadow64.tgproxy.ui

import android.content.res.Configuration
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.requiredSize
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.byshadow64.tgproxy.R
import io.github.byshadow64.tgproxy.UpdatePhase
import io.github.byshadow64.tgproxy.UpdateUiState
import io.github.byshadow64.tgproxy.ui.theme.TgProxyTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Locale

/** Synthetic update UI only: no network, APK installation or settings mutation. */
@RunWith(AndroidJUnit4::class)
class UpdateCardFeedbackTest {
    @get:Rule val compose = createComposeRule()

    @Test fun retainedVerifiedApkExplainsFailedInstallInCompactRussianDark() =
        failedInstallRemainsRetryable("ru", true)

    @Test fun retainedVerifiedApkExplainsFailedInstallInCompactEnglishLight() =
        failedInstallRemainsRetryable("en", false)

    private fun failedInstallRemainsRetryable(locale: String, dark: Boolean) {
        var installs = 0
        render(UpdateUiState(phase = UpdatePhase.READY, version = "0.1.8-dev",
            errorRes = R.string.update_install_error), locale, dark,
            TgProxyActions(onInstallUpdate = { installs++ }))
        compose.onNodeWithTag("update_status").assertTextEquals(text(R.string.update_ready, locale))
        compose.onNodeWithTag("update_error").assertIsDisplayed()
            .assertTextEquals(text(R.string.update_install_error, locale))
        compose.onNodeWithTag("update_install").performScrollTo().assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals(1, installs) }
    }

    @Test fun ordinaryNetworkErrorIsShownOnce() {
        render(UpdateUiState(phase = UpdatePhase.ERROR, errorRes = R.string.update_network_error))
        compose.onAllNodesWithText(text(R.string.update_network_error)).assertCountEquals(1)
        compose.onNodeWithTag("update_error").assertDoesNotExist()
        compose.onNodeWithTag("update_check").assertIsEnabled()
    }

    @Test fun noSuccessfulCheckDoesNotInventTimestamp() {
        render(UpdateUiState(phase = UpdatePhase.ERROR, lastChecked = 0,
            errorRes = R.string.update_network_error), settings = true)
        compose.onNodeWithTag("update_last_checked").performScrollTo()
            .assertTextEquals(text(R.string.update_not_checked))
    }

    @Test fun checkingAndFailureKeepThePreviousSuccessfulTimestamp() {
        val checked = 1_798_661_700_000L
        var state by mutableStateOf(UpdateUiState(phase = UpdatePhase.CURRENT, lastChecked = checked))
        compose.setContent {
            TgProxyTheme {
                Box(Modifier.verticalScroll(rememberScrollState())) {
                    UpdateCard(state, TgProxyActions(), settings = true)
                }
            }
        }
        compose.onNodeWithTag("update_last_checked").performScrollTo()
        val date = java.util.Date(checked)
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val expected = android.text.format.DateFormat.getDateFormat(context).format(date) + " " +
            android.text.format.DateFormat.getTimeFormat(context).format(date)
        compose.onNodeWithTag("update_last_checked").assertTextContains(expected)
        for (phase in listOf(UpdatePhase.CHECKING, UpdatePhase.ERROR)) {
            compose.runOnIdle { state = state.copy(phase = phase,
                errorRes = if (phase == UpdatePhase.ERROR) R.string.update_network_error else 0) }
            compose.onNodeWithTag("update_last_checked").performScrollTo().assertTextContains(expected)
        }
    }

    @Test fun overviewUpdateCardDoesNotAddCheckHistory() {
        render(UpdateUiState(phase = UpdatePhase.READY, lastChecked = 1_798_661_700_000L))
        compose.onNodeWithTag("update_last_checked").assertDoesNotExist()
    }

    private fun render(
        state: UpdateUiState,
        locale: String? = null,
        dark: Boolean = false,
        actions: TgProxyActions = TgProxyActions(),
        settings: Boolean = false,
    ) {
        compose.setContent {
            val configuration = Configuration(LocalConfiguration.current).apply {
                if (locale != null) setLocale(Locale.forLanguageTag(locale))
                uiMode = (uiMode and Configuration.UI_MODE_NIGHT_MASK.inv()) or
                    (if (dark) Configuration.UI_MODE_NIGHT_YES else Configuration.UI_MODE_NIGHT_NO)
                screenWidthDp = 320
                screenHeightDp = 640
            }
            val context = LocalContext.current
            val density = LocalDensity.current
            CompositionLocalProvider(
                LocalContext provides context.createConfigurationContext(configuration),
                LocalConfiguration provides configuration,
                LocalDensity provides Density(density.density, 1.3f),
            ) {
                TgProxyTheme {
                    Box(Modifier.requiredSize(320.dp, 640.dp).verticalScroll(rememberScrollState())) {
                        UpdateCard(state, actions, settings)
                    }
                }
            }
        }
    }

    private fun text(id: Int, locale: String? = null): String {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        if (locale == null) return context.getString(id)
        val configuration = Configuration(context.resources.configuration).apply {
            setLocale(Locale.forLanguageTag(locale))
        }
        return context.createConfigurationContext(configuration).getString(id)
    }
}
