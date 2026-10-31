package io.github.byshadow64.tgproxy.ui

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.hasTestTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.byshadow64.tgproxy.ConnectionAvailability
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Synthetic UI only: no services, profiles, clipboard or network are touched. */
@RunWith(AndroidJUnit4::class)
class ActionFeedbackTest {
    @get:Rule val compose = createComposeRule()

    @Test fun feedbackIsVisibleOnJournalAndDoesNotForceOverview() {
        var state by mutableStateOf(TgProxyUiState())
        compose.setContent { TgProxyApp(state, TgProxyActions()) }
        compose.onNodeWithTag("nav_2").performClick()
        compose.runOnIdle { state = state.copy(feedback = UiFeedback(1, "REPORT_COPIED")) }
        compose.onNodeWithText("REPORT_COPIED").assertIsDisplayed()
        compose.onNodeWithTag("journal_content").assertIsDisplayed()
    }

    @Test fun replacedMessageConsumesOnlyOldIdAndKeepsNewMessageAcrossNavigation() {
        var state by mutableStateOf(TgProxyUiState(feedback = UiFeedback(1, "FIRST_FEEDBACK")))
        val consumed = mutableListOf<Long>()
        compose.setContent {
            TgProxyApp(state, TgProxyActions(onFeedbackConsumed = { id ->
                consumed += id
                if (state.feedback?.id == id) state = state.copy(feedback = null)
            }))
        }
        compose.onNodeWithText("FIRST_FEEDBACK").assertIsDisplayed()
        compose.runOnIdle { state = state.copy(feedback = UiFeedback(2, "SECOND_FEEDBACK")) }
        compose.onNodeWithText("SECOND_FEEDBACK").assertIsDisplayed()
        compose.onNodeWithTag("nav_1").performClick()
        compose.onNodeWithText("SECOND_FEEDBACK").assertIsDisplayed()
        compose.runOnIdle {
            assertEquals(listOf(1L), consumed)
            assertEquals(2L, state.feedback?.id)
        }
    }

    @Test fun lossOfNetworkKeepsRunningControlsAndOffersExplicitReconnect() {
        var state by mutableStateOf(TgProxyUiState(status = ProxyStatus.RUNNING, runningPort = 1443,
            connection = ConnectionAvailability.OFFLINE))
        var reconnects = 0
        compose.setContent { TgProxyApp(state, TgProxyActions(onReconnect = { reconnects++ })) }
        compose.onNodeWithTag("overview_content").performScrollToNode(hasTestTag("reconnect_proxy"))
        compose.onNodeWithTag("reconnect_proxy").performClick()
        compose.runOnIdle { assertEquals(1, reconnects); state = state.copy(status = ProxyStatus.STOPPED) }
        compose.onNodeWithTag("reconnect_proxy").assertDoesNotExist()
    }

    @Test fun transientFeedbackNeverReplacesPersistentFailure() {
        compose.setContent {
            TgProxyApp(TgProxyUiState(status = ProxyStatus.ERROR, statusMessage = "PERSISTENT_FAILURE",
                feedback = UiFeedback(7, "ACTION_FEEDBACK")), TgProxyActions())
        }
        compose.onNodeWithText("ACTION_FEEDBACK").assertIsDisplayed()
        compose.onNodeWithTag("overview_content").performScrollToNode(androidx.compose.ui.test.hasText("PERSISTENT_FAILURE"))
        compose.onNodeWithText("PERSISTENT_FAILURE").assertIsDisplayed()
    }
}
