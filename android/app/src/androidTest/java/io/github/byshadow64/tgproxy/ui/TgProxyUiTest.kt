package io.github.byshadow64.tgproxy.ui

import android.content.res.Configuration
import android.graphics.Bitmap
import android.os.Build
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.requiredSize
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.graphics.toPixelMap
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.getUnclippedBoundsInRoot
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.test.performTextReplacement
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.byshadow64.tgproxy.R
import io.github.byshadow64.tgproxy.BuildConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.json.JSONObject
import java.io.File
import java.util.Locale

/** Fake state and callbacks only: these tests never start a service or open a network connection. */
@OptIn(ExperimentalTestApi::class)
@RunWith(AndroidJUnit4::class)
class TgProxyUiTest {
    @get:Rule
    val compose = createComposeRule()

    @Test
    fun stoppedOverviewStartsOnlyOnExplicitActionAndDisablesTelegram() {
        var starts = 0
        var opens = 0
        var copies = 0
        render(actions = TgProxyActions(onStart = { starts++ }, onOpenTelegram = { opens++ }, onCopyTelegramLink = { copies++ }), dark = false)

        compose.onNodeWithText(text(R.string.ui_status_stopped)).assertIsDisplayed()
        captureReview("overview-light", "Overview with fake STOPPED state", theme = "light")
        compose.onNodeWithTag("proxy_action").assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals(1, starts) }

        scrollTo("overview_content", "open_telegram")
        compose.onNodeWithTag("open_telegram").assertIsNotEnabled()
        scrollTo("overview_content", "copy_telegram_link")
        compose.onNodeWithTag("copy_telegram_link").assertIsNotEnabled()
        compose.runOnIdle { assertEquals(0, opens); assertEquals(0, copies) }
    }

    @Test
    fun runningOverviewDescribesLocalListenerAndRequiresTelegramHandoff() {
        var stops = 0
        var opens = 0
        var copies = 0
        render(
            state = TgProxyUiState(status = ProxyStatus.RUNNING, runningPort = 1443, hasSavedSettings = true),
            actions = TgProxyActions(onStop = { stops++ }, onOpenTelegram = { opens++ }, onCopyTelegramLink = { copies++ }),
            dark = true,
        )

        compose.onNodeWithText(text(R.string.ui_status_running)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.ui_status_running_body)).assertExists()
        compose.onNodeWithText(text(R.string.ui_status_stopped)).assertDoesNotExist()
        captureReview("overview-dark", "Overview with fake RUNNING state; no real service", theme = "dark")
        compose.onNodeWithTag("proxy_action").performClick()
        scrollTo("overview_content", "open_telegram")
        compose.onNodeWithTag("open_telegram").assertIsEnabled().performClick()
        scrollTo("overview_content", "copy_telegram_link")
        compose.onNodeWithTag("copy_telegram_link").assertIsEnabled().performClick()
        compose.runOnIdle {
            assertEquals(1, stops)
            assertEquals(1, opens)
            assertEquals(1, copies)
        }
    }

    @Test
    fun connectionLinkActionsAreDisabledThroughoutNonRunningStates() {
        var state by mutableStateOf(TgProxyUiState(status = ProxyStatus.STARTING))
        var actions = 0
        compose.setContent { TgProxyApp(state, TgProxyActions(onOpenTelegram = { actions++ }, onCopyTelegramLink = { actions++ })) }
        for (status in listOf(ProxyStatus.STARTING, ProxyStatus.STOPPING, ProxyStatus.ERROR, ProxyStatus.STOPPED)) {
            compose.runOnIdle { state = TgProxyUiState(status = status) }
            scrollTo("overview_content", "open_telegram")
            compose.onNodeWithTag("open_telegram").assertIsNotEnabled()
            scrollTo("overview_content", "copy_telegram_link")
            compose.onNodeWithTag("copy_telegram_link").assertIsNotEnabled()
        }
        compose.runOnIdle { assertEquals(0, actions) }
    }

    @Test
    fun overviewShowsAppliedPortInsteadOfSavedPendingPort() {
        var state by mutableStateOf(TgProxyUiState(status = ProxyStatus.RUNNING, runningPort = 1443,
            settings = ProxySettingsUi(localPort = "2443")))
        compose.setContent { TgProxyApp(state, TgProxyActions()) }
        compose.onNodeWithText("127.0.0.1:1443", substring = true).assertIsDisplayed()
        compose.onNodeWithText("127.0.0.1:2443", substring = true).assertDoesNotExist()
        compose.runOnIdle { state = state.copy(status = ProxyStatus.STOPPED, runningPort = null) }
        compose.onNodeWithText("127.0.0.1:2443", substring = true).assertIsDisplayed()
        compose.runOnIdle { state = state.copy(status = ProxyStatus.RUNNING) }
        compose.onNodeWithTag("proxy_endpoint").assertDoesNotExist()
    }

    @Test
    fun overviewKeepsConnectionActionsBeforeSessionStatistics() {
        render(state = TgProxyUiState(status = ProxyStatus.RUNNING, runningPort = 1443))
        compose.onNodeWithTag("import_link_overview").assertDoesNotExist()
        scrollTo("overview_content", "session_metrics")
        val copy = compose.onNodeWithTag("copy_telegram_link").assertIsDisplayed().getUnclippedBoundsInRoot()
        // The connection action must precede counters, not disappear below them.
        val metrics = compose.onNodeWithTag("session_metrics").getUnclippedBoundsInRoot()
        assertTrue("Connection actions must precede statistics", copy.bottom <= metrics.top)
        captureReview("connection-actions-first", "Fake running profile: connection actions before statistics")
    }

    @Test
    fun verifiedHelperUpdatePreservesUnrelatedDraftWithoutRestoringOldCredentials() {
        var state by mutableStateOf(TgProxyUiState(hasSavedSettings = true,
            settings = ProxySettingsUi(helperHost = "private.example.invalid", helperToken = "synthetic-old-token",
                helperCertificateSha256 = "ab".repeat(32))))
        var saved: ProxySettingsUi? = null
        compose.setContent { TgProxyApp(state, TgProxyActions(onSaveSettings = { saved = it })) }
        compose.onNodeWithTag("nav_1").performClick()
        scrollTo("routes_content", "field_localPort")
        compose.onNodeWithTag("field_localPort").performTextReplacement("2443")
        compose.onNodeWithTag("nav_2").performClick()
        compose.runOnIdle {
            state = state.copy(settings = state.settings.copy(helperEnabled = true, helperHost = "9.9.9.9",
                helperRegistryManaged = true, helperToken = "", helperCertificateSha256 = "cd".repeat(32)))
        }
        compose.onNodeWithTag("nav_1").performClick()
        scrollTo("routes_content", "field_localPort")
        assertEquals("2443", compose.onNodeWithTag("field_localPort").fetchSemanticsNode().config[SemanticsProperties.EditableText].text)
        scrollTo("routes_content", "save_settings")
        compose.onNodeWithTag("save_settings").assertIsEnabled().performClick()
        compose.runOnIdle {
            assertEquals("2443", saved?.localPort)
            assertEquals("9.9.9.9", saved?.helperHost)
            assertEquals("", saved?.helperToken)
            assertEquals("cd".repeat(32), saved?.helperCertificateSha256)
            assertEquals(true, saved?.helperRegistryManaged)
            assertEquals(true, saved?.helperEnabled)
        }
    }

    @Test
    fun savedPrivateHelperIsReadOnlyAndLocalEditsPreserveCredentials() {
        val fakeToken = "android-ui-private-token-do-not-use"
        val settings = ProxySettingsUi(helperEnabled = true, helperHost = "helper.example.invalid",
            helperPort = "8444", helperCertificateSha256 = "ab".repeat(32), helperToken = fakeToken)
        var saved: ProxySettingsUi? = null
        render(state = TgProxyUiState(settings = settings, hasSavedSettings = true),
            actions = TgProxyActions(onSaveSettings = { saved = it }))
        compose.onNodeWithTag("nav_1").performClick()
        assertNoLegacyHelperEditors()
        scrollTo("routes_content", "saved_helper_summary")
        compose.onNodeWithText("helper.example.invalid:8444").assertIsDisplayed()
        compose.onNodeWithText(fakeToken, substring = true).assertDoesNotExist()
        // The summary can be visible while this later row is covered by the
        // fixed navigation bar. performClick sends a touch; it doesn't scroll.
        scrollTo("routes_content", "helper_toggle")
        val toggleBounds = compose.onNodeWithTag("helper_toggle").assertIsDisplayed().getUnclippedBoundsInRoot()
        val navigationBounds = compose.onNodeWithTag("nav_1").getUnclippedBoundsInRoot()
        assertTrue("Toggle must be above navigation: toggle=$toggleBounds, nav=$navigationBounds",
            toggleBounds.bottom <= navigationBounds.top + 1.dp)
        compose.onNodeWithTag("helper_toggle").assertIsOn().performClick().assertIsOff()
        scrollTo("routes_content", "field_localPort")
        compose.onNodeWithTag("field_localPort").performTextReplacement("2443")
        compose.onNodeWithTag("helper_toggle").assertIsOff()
        scrollTo("routes_content", "save_settings")
        compose.onNodeWithTag("save_settings").performClick()
        compose.runOnIdle {
            assertEquals(false, saved?.helperEnabled)
            assertEquals("2443", saved?.localPort)
            assertEquals(settings.helperHost, saved?.helperHost)
            assertEquals(settings.helperPort, saved?.helperPort)
            assertEquals(settings.helperCertificateSha256, saved?.helperCertificateSha256)
            assertEquals(fakeToken, saved?.helperToken)
            assertEquals(false, saved?.helperRegistryManaged)
        }
        captureReview("saved-private-helper", "Read-only synthetic private Helper; local edits retain credentials")
    }

    @Test
    fun savingDisablesDuplicateSaveUntilPersistenceFinishes() {
        var state by mutableStateOf(TgProxyUiState(isSaving = true))
        var saves = 0
        compose.setContent {
            TgProxyApp(state, TgProxyActions(onSaveSettings = { saves++ }))
        }

        compose.onNodeWithTag("nav_1").performClick()
        scrollTo("routes_content", "save_settings")
        compose.onNodeWithTag("save_settings").assertIsNotEnabled()
        compose.runOnIdle {
            assertEquals(0, saves)
            state = state.copy(isSaving = false)
        }
        compose.onNodeWithTag("save_settings").assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals(1, saves) }
    }

    @Test
    fun runningSettingsRequireExplicitRestartConfirmation() {
        var restarts = 0
        var saves = 0
        var appliedPort: String? = null
        render(
            state = TgProxyUiState(status = ProxyStatus.RUNNING, hasSavedSettings = true),
            actions = TgProxyActions(
                onSaveSettings = { saves++ },
                onRestartWithSettings = { restarts++; appliedPort = it.localPort },
            ),
        )

        compose.onNodeWithTag("nav_1").performClick()
        scrollTo("routes_content", "field_localPort")
        compose.onNodeWithTag("field_localPort").performTextReplacement("2443")
        scrollTo("routes_content", "save_settings")
        compose.onNodeWithTag("save_settings").assertIsEnabled().performClick()
        compose.onNodeWithText(text(R.string.ui_restart_title)).assertIsDisplayed()
        compose.runOnIdle {
            assertEquals(0, restarts)
            assertEquals(0, saves)
        }
        compose.onNodeWithText(text(R.string.ui_restart_confirm)).performClick()
        compose.runOnIdle {
            assertEquals(1, restarts)
            assertEquals("2443", appliedPort)
            assertEquals(0, saves)
        }
    }

    @Test
    fun journalFiltersInfoWarningAndErrorEvents() {
        render(state = TgProxyUiState(journal = listOf(
            JournalEntry(1, "10:00:00", LogLevel.INFO, "ui-info-event"),
            JournalEntry(2, "10:00:01", LogLevel.WARNING, "ui-warning-event"),
            JournalEntry(3, "10:00:02", LogLevel.ERROR, "ui-error-event"),
        )))
        compose.onNodeWithTag("nav_2").performClick()
        compose.onNodeWithTag("journal_event_3").assertIsDisplayed()
        captureReview("journal", "Journal with three synthetic INFO, WARNING and ERROR events")

        compose.onNodeWithTag("journal_filter_3").performClick().assertIsSelected()
        compose.onNodeWithTag("journal_event_3").assertIsDisplayed()
        compose.onNodeWithTag("journal_event_1").assertDoesNotExist()
        compose.onNodeWithTag("journal_event_2").assertDoesNotExist()

        compose.onNodeWithTag("journal_filter_2").performClick().assertIsSelected()
        compose.onNodeWithTag("journal_event_2").assertIsDisplayed()
        compose.onNodeWithTag("journal_event_1").assertDoesNotExist()
        compose.onNodeWithTag("journal_event_3").assertDoesNotExist()

        compose.onNodeWithTag("journal_filter_1").performClick().assertIsSelected()
        compose.onNodeWithTag("journal_event_1").assertIsDisplayed()
        compose.onNodeWithTag("journal_event_2").assertDoesNotExist()
        compose.onNodeWithTag("journal_event_3").assertDoesNotExist()
    }

    @Test
    fun compactLightLayoutScrollsAtLargerFontScale() = assertCompactLayout(dark = false)

    @Test
    fun compactDarkLayoutScrollsAtLargerFontScale() = assertCompactLayout(dark = true)

    @Test
    fun ownerLogoHeaderRussianLightKeepsControlsUsable() = assertOwnerLogoHeader("ru", dark = false)

    @Test
    fun ownerLogoHeaderRussianDarkKeepsControlsUsable() = assertOwnerLogoHeader("ru", dark = true)

    @Test
    fun ownerLogoHeaderEnglishLightKeepsControlsUsable() = assertOwnerLogoHeader("en", dark = false)

    @Test
    fun ownerLogoHeaderEnglishDarkKeepsControlsUsable() = assertOwnerLogoHeader("en", dark = true)

    @Test
    fun ipDraftIsSeparateFromSavedSettingsUntilVerifiedConnection() {
        val original = ProxySettingsUi(helperEnabled = true, helperHost = "private.example.invalid",
            helperCertificateSha256 = "ab".repeat(32), helperToken = "synthetic-private-token-do-not-use")
        var state by mutableStateOf(TgProxyUiState(settings = original, hasSavedSettings = true))
        var requests = 0
        var requestedIp = ""
        var saved: ProxySettingsUi? = null
        compose.setContent { TgProxyApp(state, TgProxyActions(
            onSaveSettings = { saved = it; state = state.copy(settings = it) },
            onConnectHelperIp = { requests++; requestedIp = it; state = state.copy(pairingStatus = PairingStatus.CONNECTING) },
        )) }
        compose.onNodeWithTag("nav_1").performClick()
        assertNoLegacyHelperEditors()
        compose.onNodeWithTag("field_pairHost").performTextReplacement("9.9.9.9")
        scrollTo("routes_content", "field_localPort")
        compose.onNodeWithTag("field_localPort").performTextReplacement("2443")
        scrollTo("routes_content", "save_settings")
        compose.onNodeWithTag("save_settings").performClick()
        compose.runOnIdle {
            assertEquals(0, requests)
            assertEquals(original.helperHost, saved?.helperHost)
            assertEquals(original.helperToken, saved?.helperToken)
        }
        scrollTo("routes_content", "connect_helper_ip")
        compose.onNodeWithTag("connect_helper_ip").performClick().assertIsNotEnabled()
        compose.runOnIdle {
            assertEquals(1, requests); assertEquals("9.9.9.9", requestedIp)
            assertEquals(original.helperHost, state.settings.helperHost)
            state = state.copy(pairingStatus = PairingStatus.SUCCESS,
                settings = state.settings.copy(helperEnabled = true, helperHost = requestedIp,
                    helperCertificateSha256 = "cd".repeat(32), helperToken = "", helperRegistryManaged = true))
        }
        scrollTo("routes_content", "saved_helper_summary")
        compose.onNodeWithText("9.9.9.9:8444").assertIsDisplayed()
        assertNoLegacyHelperEditors()
    }

    @Test
    fun ipConnectionCannotChangeRunningProxy() {
        var requests = 0
        render(state = TgProxyUiState(status = ProxyStatus.RUNNING), actions = TgProxyActions(onConnectHelperIp = { requests++ }))
        compose.onNodeWithTag("nav_1").performClick()
        compose.onNodeWithTag("field_pairHost").assertIsNotEnabled()
        scrollTo("routes_content", "connect_helper_ip")
        compose.onNodeWithTag("connect_helper_ip").assertIsNotEnabled()
        compose.onNodeWithText(text(R.string.registry_stop_first)).assertExists()
        assertNoLegacyHelperEditors()
        compose.runOnIdle { assertEquals(0, requests) }
    }

    @Test
    fun ipErrorsNeverExposeStoredPrivateCredentials() {
        val fakeToken = "synthetic-private-token-must-stay-hidden"
        val state = TgProxyUiState(settings = ProxySettingsUi(helperEnabled = true,
            helperHost = "private.example.invalid", helperCertificateSha256 = "ab".repeat(32), helperToken = fakeToken),
            pairingStatus = PairingStatus.ERROR, pairingMessage = "ui-test-registry-rejected",
            pairingValidationErrors = mapOf(PairingFields.HOST to "ui-test-ip-error"))
        render(state = state)
        compose.onNodeWithTag("nav_1").performClick()
        compose.onNodeWithText("ui-test-ip-error").assertExists()
        scrollTo("routes_content", "registry_message")
        compose.onNodeWithTag("registry_message").assertIsDisplayed()
        assertNoLegacyHelperEditors()
        compose.onAllNodes(SemanticsMatcher("Display text leaks private token") { node ->
            node.config.getOrNull(SemanticsProperties.Text)?.any { it.text.contains(fakeToken) } == true
        }).assertCountEquals(0)
        compose.runOnIdle { assertFalse(state.toString().contains(fakeToken)) }
    }

    @Test
    fun registryPrimaryConnectsOnlyOnClickHasNoOwnerCodeAndCanCancel() {
        var state by mutableStateOf(TgProxyUiState())
        var requests = 0; var cancellations = 0; var target = ""
        compose.setContent { TgProxyApp(state, TgProxyActions(
            onConnectHelperIp = { requests++; target = it; state = state.copy(pairingStatus = PairingStatus.CONNECTING, isSaving = true) },
            onCancelHelperConnect = { cancellations++ },
        )) }
        compose.onNodeWithTag("nav_1").performClick()
        compose.onNodeWithTag("field_pairCode").assertDoesNotExist()
        scrollTo("routes_content", "field_pairHost")
        compose.onNodeWithTag("field_pairHost").performTextReplacement(" 192.0.2.10 ")
        compose.runOnIdle { assertEquals(0, requests) }
        scrollTo("routes_content", "connect_helper_ip")
        compose.onNodeWithTag("connect_helper_ip").performClick().assertIsNotEnabled()
        compose.runOnIdle { assertEquals(1, requests); assertEquals("192.0.2.10", target) }
        scrollTo("routes_content", "cancel_helper_ip")
        compose.onNodeWithTag("cancel_helper_ip").performClick()
        compose.runOnIdle { assertEquals(1, cancellations) }
    }

    @Test
    fun unknownHelperOffersSshSetupWithoutPasswordBeforeKeyVerification() {
        render(state = TgProxyUiState(pairingStatus = PairingStatus.ERROR, registrySetupRequired = true,
            pairingMessage = "synthetic-unregistered-helper"))
        compose.onNodeWithTag("nav_1").performClick()
        scrollTo("routes_content", "helper_setup_instructions")
        compose.onNodeWithTag("helper_setup_instructions").performClick()
        compose.onNodeWithTag("ssh_setup").assertExists()
        compose.onNodeWithTag("ssh_password").assertDoesNotExist()
        compose.onNodeWithTag("field_pairCode").assertDoesNotExist()
    }

    @Test
    fun sshKeyMustBeConfirmedBeforePasswordAndInstallationAreAvailable() {
        val fakePassword = "SYNTHETIC-UI-ONLY-SSH-PASSWORD"
        var state by mutableStateOf(TgProxyUiState(pairingStatus = PairingStatus.ERROR, registrySetupRequired = true))
        var probes = 0; var deployments = 0; var cancellations = 0
        compose.setContent { TgProxyApp(state, TgProxyActions(
            onProbeHelperSsh = { host, port, user ->
                probes++
                state = state.copy(sshSetup = SshSetupUiState(SshSetupPhase.CONFIRM_HOST_KEY, host, port.toInt(), user,
                    "ecdsa-sha2-nistp256", "SHA256:synthetic-hostkey-not-real"))
            },
            onConfirmHelperSshKey = { state = state.copy(sshSetup = state.sshSetup.copy(phase = SshSetupPhase.READY)) },
            onDeployHelperSsh = { password, access, upgrade ->
                assertEquals(fakePassword, String(password)); assertTrue(access); assertFalse(upgrade)
                password.fill('\u0000'); deployments++
                state = state.copy(isSaving = true, sshSetup = state.sshSetup.copy(phase = SshSetupPhase.DEPLOYING))
            },
            onCancelHelperSsh = { cancellations++ },
        )) }
        compose.onNodeWithTag("nav_1").performClick()
        scrollTo("routes_content", "helper_setup_instructions"); compose.onNodeWithTag("helper_setup_instructions").performClick()
        scrollTo("routes_content", "ssh_host"); compose.onNodeWithTag("ssh_host").performTextReplacement("192.0.2.10")
        scrollTo("routes_content", "ssh_probe"); compose.onNodeWithTag("ssh_probe").performClick()
        compose.runOnIdle { assertEquals(1, probes); assertEquals(0, deployments) }
        compose.onNodeWithTag("ssh_password").assertDoesNotExist()
        scrollTo("routes_content", "ssh_confirm_key"); compose.onNodeWithTag("ssh_confirm_key").assertIsNotEnabled()
        scrollTo("routes_content", "ssh_key_checked"); compose.onNodeWithTag("ssh_key_checked").performClick()
        scrollTo("routes_content", "ssh_confirm_key"); compose.onNodeWithTag("ssh_confirm_key").performClick()
        scrollTo("routes_content", "ssh_password")
        compose.onNodeWithTag("ssh_password").assert(SemanticsMatcher.keyIsDefined(SemanticsProperties.Password)).performTextReplacement(fakePassword)
        scrollTo("routes_content", "ssh_deploy"); compose.onNodeWithTag("ssh_deploy").assertIsNotEnabled()
        scrollTo("routes_content", "ssh_registered_access")
        compose.onNodeWithTag("ssh_registered_access").assertIsOff().performClick().assertIsOn()
        scrollTo("routes_content", "ssh_deploy"); compose.onNodeWithTag("ssh_deploy").performClick()
        compose.runOnIdle { assertEquals(1, deployments); assertFalse(state.toString().contains(fakePassword)) }
        compose.onNodeWithTag("ssh_password").assertDoesNotExist()
        scrollTo("routes_content", "ssh_cancel"); compose.onNodeWithTag("ssh_cancel").performClick()
        compose.runOnIdle { assertEquals(1, cancellations) }
    }

    @Test
    fun activeSshSetupRemainsCancelableAfterTabNavigationAndBlocksStart() {
        var starts = 0; var cancellations = 0
        // Do not rely on isSaving: all live setup phases must independently
        // disable starting a proxy that would conflict with server setup.
        render(state = TgProxyUiState(sshSetup = SshSetupUiState(phase = SshSetupPhase.DEPLOYING,
            host = "192.0.2.10", progressMessage = "Synthetic deployment in progress")),
            actions = TgProxyActions(onStart = { starts++ }, onCancelHelperSsh = { cancellations++ }))
        compose.onNodeWithTag("proxy_action").assertIsNotEnabled()
        compose.onNodeWithTag("nav_1").performClick()
        scrollTo("routes_content", "ssh_cancel")
        compose.onNodeWithTag("ssh_cancel").assertIsDisplayed()
        compose.onNodeWithTag("nav_2").performClick()
        compose.onNodeWithTag("nav_1").performClick()
        scrollTo("routes_content", "ssh_cancel")
        compose.onNodeWithTag("ssh_cancel").assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals(0, starts); assertEquals(1, cancellations) }
    }

    @Test
    fun leavingSshReadyScreenClearsPasswordAndPublicAccessConsent() {
        render(state = TgProxyUiState(sshSetup = SshSetupUiState(phase = SshSetupPhase.READY, host = "192.0.2.10")))
        compose.onNodeWithTag("nav_1").performClick()
        scrollTo("routes_content", "ssh_password")
        compose.onNodeWithTag("ssh_password").performTextReplacement("synthetic-ui-password")
        scrollTo("routes_content", "ssh_registered_access")
        compose.onNodeWithTag("ssh_registered_access").assertIsOff().performClick()
        compose.onNodeWithTag("nav_2").performClick()
        compose.onNodeWithTag("nav_1").performClick()
        scrollTo("routes_content", "ssh_password")
        assertEquals("", compose.onNodeWithTag("ssh_password").fetchSemanticsNode().config[SemanticsProperties.EditableText].text)
        scrollTo("routes_content", "ssh_registered_access")
        compose.onNodeWithTag("ssh_registered_access").assertIsOff()
        scrollTo("routes_content", "ssh_deploy")
        compose.onNodeWithTag("ssh_deploy").assertIsNotEnabled()
    }

    @Test
    fun resetSshWizardDoesNotTransferConsentToAnotherEndpointWithSameKey() {
        var state by mutableStateOf(TgProxyUiState(registrySetupRequired = true, sshSetup = SshSetupUiState(phase = SshSetupPhase.READY,
            host = "192.0.2.10", fingerprint = "SHA256:synthetic-same-test-key")))
        compose.setContent { TgProxyApp(state, TgProxyActions(
            onResetHelperSsh = { state = state.copy(sshSetup = SshSetupUiState()) },
            onProbeHelperSsh = { host, port, user ->
                state = state.copy(sshSetup = SshSetupUiState(phase = SshSetupPhase.CONFIRM_HOST_KEY,
                    host = host, port = port.toInt(), user = user, fingerprint = "SHA256:synthetic-same-test-key"))
            },
            onConfirmHelperSshKey = { state = state.copy(sshSetup = state.sshSetup.copy(phase = SshSetupPhase.READY)) },
        )) }
        compose.onNodeWithTag("nav_1").performClick()
        scrollTo("routes_content", "ssh_password")
        compose.onNodeWithTag("ssh_password").performTextReplacement("synthetic-ui-password")
        scrollTo("routes_content", "ssh_registered_access")
        compose.onNodeWithTag("ssh_registered_access").performClick().assertIsOn()
        scrollTo("routes_content", "ssh_allow_upgrade")
        compose.onNodeWithTag("ssh_allow_upgrade").performClick().assertIsOn()
        scrollTo("routes_content", "ssh_reset")
        compose.onNodeWithTag("ssh_reset").performClick()
        // Follow the actual INPUT -> CONFIRM_HOST_KEY -> READY flow. The former
        // direct READY injection hit an API 26 pending-layout timeout after the
        // tall lazy item collapsed; it also skipped the required user actions.
        scrollTo("routes_content", "ssh_host")
        compose.onNodeWithTag("ssh_host").performTextReplacement("192.0.2.20")
        scrollTo("routes_content", "ssh_probe")
        compose.onNodeWithTag("ssh_probe").assertIsEnabled().performClick()
        scrollTo("routes_content", "ssh_key_checked")
        compose.onNodeWithTag("ssh_key_checked").assertIsOff().performClick()
        scrollTo("routes_content", "ssh_confirm_key")
        compose.onNodeWithTag("ssh_confirm_key").performClick()
        scrollTo("routes_content", "ssh_password")
        assertEquals("", compose.onNodeWithTag("ssh_password").fetchSemanticsNode().config[SemanticsProperties.EditableText].text)
        scrollTo("routes_content", "ssh_registered_access")
        compose.onNodeWithTag("ssh_registered_access").assertIsOff()
        scrollTo("routes_content", "ssh_allow_upgrade")
        compose.onNodeWithTag("ssh_allow_upgrade").assertIsOff()
        scrollTo("routes_content", "ssh_deploy")
        compose.onNodeWithTag("ssh_deploy").assertIsNotEnabled()
    }

    private fun assertCompactLayout(dark: Boolean) {
        render(compact = true, dark = dark)
        compose.onNodeWithTag("nav_0").assertIsDisplayed()
        val navigationBounds = compose.onNodeWithTag("nav_0").getUnclippedBoundsInRoot()
        assertTrue("Navigation targets must be at least 48dp tall", navigationBounds.bottom - navigationBounds.top >= 48.dp)
        val rootBounds = compose.onNodeWithTag("app_root").getUnclippedBoundsInRoot()
        assertEquals(320f, (rootBounds.right - rootBounds.left).value, 0.5f)
        val background = compose.onNodeWithTag("app_root").captureToImage().toPixelMap()[1, 1]
        assertTrue("The UI must follow system night mode", if (dark) background.luminance() < 0.3f else background.luminance() > 0.7f)
        captureReview(
            "overview-${if (dark) "dark" else "light"}-compact",
            "Overview with fake STOPPED state, 320x640dp viewport and 1.3 font scale",
            theme = if (dark) "dark" else "light",
            compact = true,
        )

        scrollTo("overview_content", "proxy_action")
        compose.onNodeWithTag("proxy_action").assertIsDisplayed().assertIsEnabled()
        compose.onNodeWithTag("nav_1").performClick()
        scrollTo("routes_content", "save_settings")
        compose.onNodeWithTag("save_settings").assertIsDisplayed().assertIsEnabled()
        val saveBounds = compose.onNodeWithTag("save_settings").getUnclippedBoundsInRoot()
        assertTrue("Save targets must be at least 48dp tall", saveBounds.bottom - saveBounds.top >= 48.dp)
    }

    private fun assertOwnerLogoHeader(localeTag: String, dark: Boolean) {
        var starts = 0
        render(
            actions = TgProxyActions(onStart = { starts++ }),
            compact = true,
            dark = dark,
            localeTag = localeTag,
        )
        val logo = compose.onNodeWithTag("header_brand_logo").assertIsDisplayed()
        val bounds = logo.getUnclippedBoundsInRoot()
        assertEquals(40f, (bounds.right - bounds.left).value, 0.5f)
        assertEquals(40f, (bounds.bottom - bounds.top).value, 0.5f)
        compose.onNodeWithText(text(R.string.ui_app_title, localeTag)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.ui_byline, localeTag)).assertIsDisplayed()
        compose.onNodeWithTag("dev_disclaimer").assertIsDisplayed()
        compose.onNodeWithText(text(R.string.ui_dev_disclaimer, localeTag)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.ui_overview, localeTag)).assertIsDisplayed()

        // The owner's artwork has blue/white detail; the green launcher mark is a separate asset.
        val logoPixels = logo.captureToImage().toPixelMap()
        var blueDetailPixels = 0
        for (y in 0 until logoPixels.height) {
            for (x in 0 until logoPixels.width) {
                val color = logoPixels[x, y]
                if (color.blue > 0.2f && color.blue > color.green + 0.02f && color.blue > color.red + 0.05f) {
                    blueDetailPixels++
                }
            }
        }
        assertTrue("The header must render the owner's blue cat artwork", blueDetailPixels > 5)
        captureReview(
            "header-$localeTag-${if (dark) "dark" else "light"}",
            "Owner cat-logo header with fake STOPPED state; 320x640dp and 1.3 font scale",
            theme = if (dark) "dark" else "light",
            compact = true,
            localeTag = localeTag,
        )

        scrollTo("overview_content", "proxy_action")
        compose.onNodeWithTag("proxy_action").assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals(1, starts) }
        compose.onNodeWithTag("nav_1").performClick().assertIsSelected()
        compose.onNodeWithTag("header_brand_logo").assertIsDisplayed()
        scrollTo("routes_content", "field_pairHost")
        compose.onNodeWithTag("field_pairHost").assertIsDisplayed().assertIsEnabled()
        compose.onNodeWithTag("nav_2").performClick().assertIsSelected()
        compose.onNodeWithTag("header_brand_logo").assertIsDisplayed()
        compose.onNodeWithText(text(R.string.ui_journal_title, localeTag)).assertIsDisplayed()
    }

    @Test
    fun helperLinkOnlyConnectsAfterPreviewAndConfirmation() {
        var connections = 0
        var saves = 0
        var receivedIp = ""
        render(actions = TgProxyActions(
            onConnectHelperIp = { receivedIp = it; connections++ },
            onSaveSettings = { saves++ },
        ))
        openLinkDialog()
        compose.onNodeWithTag("field_import_link").assert(SemanticsMatcher.keyIsDefined(SemanticsProperties.Password))
            .performTextReplacement("tgproxy://helper?ip=9.9.9.9")
        compose.onNodeWithTag("preview_import_link").performClick()
        compose.onNodeWithTag("link_preview_host").assertIsDisplayed()
        compose.runOnIdle { assertEquals(0, connections); assertEquals(0, saves) }
        compose.onNodeWithTag("confirm_import_link").assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals(1, connections); assertEquals("9.9.9.9", receivedIp); assertEquals(0, saves) }
        compose.onNodeWithTag("nav_1").assertIsSelected()
        compose.onNodeWithTag("link_dialog").assertDoesNotExist()
    }

    @Test
    fun remoteTelegramLinkStaysSeparateFromHelperAndMasksSecret() {
        val syntheticSecret = "0123456789abcdef0123456789abcdef"
        var remote = 0
        var helper = 0
        var local = 0
        var opened: TelegramProxyLink? = null
        render(state = TgProxyUiState(status = ProxyStatus.RUNNING), actions = TgProxyActions(
            onOpenImportedTelegramProxy = { opened = it; remote++ },
            onConnectHelperIp = { helper++ }, onOpenTelegram = { local++ },
        ))
        openLinkDialog()
        compose.onNodeWithTag("field_import_link")
            .performTextReplacement("https://t.me/proxy?server=proxy.example.invalid&port=443&secret=dd$syntheticSecret")
        compose.onNodeWithTag("preview_import_link").performClick()
        compose.onNodeWithText(text(R.string.link_remote_title)).assertIsDisplayed()
        compose.onNodeWithTag("link_preview_mask").assertIsDisplayed()
        val layouts = mutableListOf<TextLayoutResult>()
        compose.onNodeWithTag("field_import_link").performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(layouts) }
        compose.runOnIdle {
            assertEquals(0, remote); assertEquals(0, helper); assertEquals(0, local)
            assertTrue(layouts.none { it.layoutInput.text.text.contains(syntheticSecret) })
        }
        compose.onNodeWithTag("confirm_import_link").performClick()
        compose.runOnIdle {
            assertEquals(1, remote); assertEquals(0, helper); assertEquals(0, local)
            assertEquals("proxy.example.invalid", opened?.host)
            assertFalse(opened.toString().contains(syntheticSecret))
        }
    }

    @Test
    fun loopbackLinkUsesCurrentPhoneActionAndRequiresRunningProxy() {
        var state by mutableStateOf(TgProxyUiState())
        var local = 0
        var remote = 0
        compose.setContent { TgProxyApp(state, TgProxyActions(onOpenTelegram = { local++ }, onOpenImportedTelegramProxy = { remote++ })) }
        openLinkDialog()
        compose.onNodeWithTag("field_import_link").performTextReplacement(
            "tg://proxy?server=127.0.0.1&port=9999&secret=dd0123456789abcdef0123456789abcdef")
        compose.onNodeWithTag("preview_import_link").performClick()
        compose.onNodeWithTag("confirm_import_link").assertIsNotEnabled()
        compose.runOnIdle { assertEquals(0, local); assertEquals(0, remote); state = state.copy(status = ProxyStatus.RUNNING) }
        compose.onNodeWithTag("confirm_import_link").assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals(1, local); assertEquals(0, remote) }
    }

    @Test
    fun runningProxyDoesNotApplyImportedHelper() {
        var connects = 0
        render(state = TgProxyUiState(status = ProxyStatus.RUNNING), actions = TgProxyActions(onConnectHelperIp = { connects++ }))
        openLinkDialog()
        compose.onNodeWithTag("field_import_link").performTextReplacement("tgproxy://helper?ip=9.9.9.9")
        compose.onNodeWithTag("preview_import_link").performClick()
        compose.onNodeWithTag("confirm_import_link").assertIsNotEnabled()
        compose.runOnIdle { assertEquals(0, connects) }
    }

    @Test
    fun invalidLinkShowsSafeErrorAndDismissClearsMemoryEditor() {
        render()
        openLinkDialog()
        compose.onNodeWithTag("field_import_link").performTextReplacement(
            "tgproxy://helper?ip=9.9.9.9&token=synthetic-secret-not-supported")
        compose.onNodeWithTag("preview_import_link").performClick()
        compose.onNodeWithText(text(R.string.link_invalid)).assertExists()
        val layouts = mutableListOf<TextLayoutResult>()
        compose.onNodeWithTag("field_import_link").performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(layouts) }
        compose.runOnIdle { assertTrue(layouts.none { it.layoutInput.text.text.contains("synthetic-secret-not-supported") }) }
        compose.onNodeWithTag("confirm_import_link").assertDoesNotExist()
        compose.onNodeWithTag("dismiss_import_link").performClick()
        openLinkDialog()
        assertEquals("", compose.onNodeWithTag("field_import_link").fetchSemanticsNode().config[SemanticsProperties.EditableText].text)
    }

    @Test
    fun incomingHelperLinkOnlyOpensPreviewAndConsumesRamPointer() {
        var state by mutableStateOf(TgProxyUiState(incomingHelperLink = ProxyLinkParser.helperLink("9.9.9.9")))
        var consumed = 0
        var connected = 0
        compose.setContent { TgProxyApp(state, TgProxyActions(
            onConsumeIncomingHelperLink = { consumed++; state = state.copy(incomingHelperLink = null) },
            onConnectHelperIp = { connected++ },
        )) }
        compose.onNodeWithTag("link_dialog").assertExists()
        compose.onNodeWithTag("link_preview_host").assertExists()
        compose.runOnIdle { assertEquals(1, consumed); assertEquals(0, connected) }
        compose.onNodeWithTag("confirm_import_link").performClick()
        compose.runOnIdle { assertEquals(1, connected) }
    }

    @Test
    fun configuredRegistryHelperCopiesOnlyItsPublicIpLink() {
        var copied: HelperIpLink? = null
        render(state = TgProxyUiState(settings = ProxySettingsUi(
            helperEnabled = true, helperRegistryManaged = true, helperHost = "9.9.9.9",
            helperCertificateSha256 = "ab".repeat(32), helperToken = "",
        ), pairingStatus = PairingStatus.SUCCESS, pairingMessage = "synthetic-previous-helper-verified"),
            actions = TgProxyActions(onCopyHelperLink = { copied = it }))
        compose.onNodeWithTag("nav_1").performClick()
        scrollTo("routes_content", "field_pairHost")
        compose.onNodeWithTag("field_pairHost").performTextReplacement("192.0.2.20")
        compose.onNodeWithTag("registry_message").assertDoesNotExist()
        scrollTo("routes_content", "copy_helper_link")
        compose.runOnIdle { assertEquals(null, copied) }
        compose.onNodeWithTag("copy_helper_link").performClick()
        compose.runOnIdle {
            assertEquals("tgproxy://helper?ip=9.9.9.9", copied?.uri)
            assertFalse(copied!!.uri.contains("token"))
            assertFalse(copied!!.uri.contains("pin"))
            assertFalse(copied!!.uri.contains("secret"))
        }
    }

    @Test fun helpCompactRuLight() = helpCompact("ru", false)
    @Test fun helpCompactRuDark() = helpCompact("ru", true)
    @Test fun helpCompactEnLight() = helpCompact("en", false)
    @Test fun helpCompactEnDark() = helpCompact("en", true)
    @Test fun linkDialogCompactRuLight() = linkCompact("ru", false, "tgproxy://helper?ip=9.9.9.9")
    @Test fun linkDialogCompactEnDark() = linkCompact("en", true,
        "tg://proxy?server=proxy.example.invalid&port=443&secret=dd0123456789abcdef0123456789abcdef")

    private fun linkCompact(locale: String, dark: Boolean, link: String) {
        render(compact = true, localeTag = locale, dark = dark)
        openLinkDialog()
        compose.onNodeWithTag("field_import_link").performTextReplacement(link)
        compose.onNodeWithTag("preview_import_link").performClick()
        compose.onNodeWithTag("confirm_import_link").assertIsDisplayed().assertIsEnabled()
        val bounds = compose.onNodeWithTag("link_dialog").getUnclippedBoundsInRoot()
        assertTrue("The dialog must fit the small viewport", (bounds.right - bounds.left).value <= 320.5f)
        captureReview("link-$locale", "Link preview with synthetic input; no network or configuration applied",
            compact = true, localeTag = locale, theme = if (dark) "dark" else "light",
            syntheticTokenMasked = true, targetTag = "link_dialog")
    }

    @Test
    fun helpQuickStartAndOptionalTopicsLeadToExistingActions() {
        var connections = 0
        render(actions = TgProxyActions(onConnectHelperIp = { connections++ }))
        compose.onNodeWithTag("nav_3").performClick()
        compose.onNodeWithTag("help_start_steps").assertExists()
        compose.onNodeWithTag("import_link_help").assertDoesNotExist()
        compose.onNodeWithTag("help_battery").assertDoesNotExist()
        scrollTo("help_content", "help_overview")
        compose.onNodeWithTag("help_overview").performClick()
        compose.onNodeWithTag("nav_0").assertIsSelected()
        compose.onNodeWithTag("nav_3").performClick()
        scrollTo("help_content", "help_helper_toggle")
        compose.onNodeWithTag("help_helper_toggle").performClick()
        scrollTo("help_content", "help_routes")
        compose.onNodeWithTag("help_routes").performClick()
        compose.onNodeWithTag("nav_1").assertIsSelected()
        compose.onNodeWithTag("nav_3").performClick()
        // Help is informational: opening it must not enroll a device or start a proxy.
        compose.runOnIdle { assertEquals(0, connections) }
        scrollTo("help_content", "help_helper_toggle")
        compose.onNodeWithTag("help_helper_toggle").performClick()
        scrollTo("help_content", "import_link_help")
        compose.onNodeWithTag("import_link_help").performClick()
        compose.onNodeWithTag("link_dialog").assertIsDisplayed()
        compose.onNodeWithTag("dismiss_import_link").performClick()
        scrollTo("help_content", "help_helper_toggle")
        compose.onNodeWithTag("help_helper_toggle").performClick()
        compose.onNodeWithTag("import_link_help").assertDoesNotExist()
    }

    @Test fun telegramActionCompactRuLight() = telegramActionCompact("ru", false)
    @Test fun telegramActionCompactRuDark() = telegramActionCompact("ru", true)
    @Test fun telegramActionCompactEnLight() = telegramActionCompact("en", false)
    @Test fun telegramActionCompactEnDark() = telegramActionCompact("en", true)

    private fun telegramActionCompact(locale: String, dark: Boolean) {
        var opens = 0
        render(state = TgProxyUiState(status = ProxyStatus.RUNNING, runningPort = 1443),
            actions = TgProxyActions(onOpenTelegram = { opens++ }), compact = true, localeTag = locale, dark = dark)
        scrollTo("overview_content", "open_telegram")
        val layouts = mutableListOf<TextLayoutResult>()
        compose.onNodeWithText(text(R.string.ui_open_telegram, locale), useUnmergedTree = true)
            .assertIsDisplayed().performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(layouts) }
        compose.runOnIdle {
            assertTrue("Open in Telegram label must be measured", layouts.isNotEmpty())
            layouts.forEach { layout ->
                assertFalse("Telegram action label must not clip vertically", layout.didOverflowHeight)
                assertTrue("Telegram action label must not ellipsize", (0 until layout.lineCount).all { !layout.isLineEllipsized(it) })
            }
        }
        compose.onNodeWithTag("open_telegram").assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals(1, opens) }
        captureReview("open-telegram-" + locale + (if (dark) "-dark" else "-light"),
            "Fake running profile; renamed action and callback on a compact large-font viewport",
            compact = true, localeTag = locale, theme = if (dark) "dark" else "light")
    }

    private fun helpCompact(locale: String, dark: Boolean) {
        var notifications = 0
        var battery = 0
        render(actions = TgProxyActions(onOpenNotificationSettings = { notifications++ }, onOpenBatterySettings = { battery++ }),
            compact = true, localeTag = locale, dark = dark)
        compose.onNodeWithTag("nav_3").performClick().assertIsSelected()
        compose.onNodeWithTag("header_brand_logo").assertIsDisplayed()
        compose.onNodeWithText(text(R.string.help_subtitle, locale)).assertIsDisplayed()
        val routeLabels = mutableListOf<TextLayoutResult>()
        compose.onNodeWithText(text(R.string.nav_routes, locale), useUnmergedTree = true)
            .assertIsDisplayed().performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(routeLabels) }
        compose.runOnIdle {
            val measurements = routeLabels.joinToString(" | ") { result ->
                "text=" + result.layoutInput.text.text + ",size=" + result.size +
                    ",constraints=" + result.layoutInput.constraints +
                    ",font=" + result.layoutInput.style.fontSize + ",lineHeight=" + result.layoutInput.style.lineHeight +
                    ",widthOverflow=" + result.didOverflowWidth + ",heightOverflow=" + result.didOverflowHeight +
                    ",lineCount=" + result.lineCount + ",maxLines=" + result.layoutInput.maxLines +
                    if (result.lineCount > 0) {
                        ",lineWidth=" + (result.getLineRight(0) - result.getLineLeft(0)) + ",lineLeft=" + result.getLineLeft(0) +
                            ",lineRight=" + result.getLineRight(0) + ",lineTop=" + result.getLineTop(0) +
                            ",lineBottom=" + result.getLineBottom(0) + ",lineBaseline=" + result.getLineBaseline(0) +
                            ",lineStart=" + result.getLineStart(0) + ",lineEnd=" + result.getLineEnd(0) +
                            ",visibleEnd=" + result.getLineEnd(0, visibleEnd = true) + ",ellipsis=" + result.isLineEllipsized(0) +
                            ",glyphs=" + result.layoutInput.text.text.indices.joinToString { result.getBoundingBox(it).toString() }
                    } else ""
            }
            assertTrue("The compact route label must be fully visible; locale=$locale,count=" +
                routeLabels.size + "; " + measurements, routeLabels.isNotEmpty() &&
                routeLabels.all { navLabelFitsMeasuredBounds(it) })
            // A shrink-wrapped Text may report didOverflowWidth because its
            // paragraph column is 194px while the node is only 116px. Actual
            // glyph bounds, not that flag, establish that the label is visible.
            routeLabels.forEach { result ->
                val last = result.getBoundingBox(result.layoutInput.text.length - 1)
                assertFalse("The geometry detector must reject a clipped final glyph",
                    navLabelFitsMeasuredBounds(result, measuredWidth = last.right - 2f))
            }
        }
        compose.runOnIdle { assertEquals(0, notifications); assertEquals(0, battery) }
        compose.onNodeWithTag("help_notifications").assertDoesNotExist()
        scrollTo("help_content", "help_background_toggle")
        compose.onNodeWithTag("help_background_toggle").performClick()
        scrollTo("help_content", "help_notifications")
        compose.onNodeWithTag("help_notifications").assertIsEnabled().performClick()
        scrollTo("help_content", "help_battery")
        compose.onNodeWithTag("help_battery").assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals(1, notifications); assertEquals(1, battery) }
        scrollTo("help_content", "help_devices")
        compose.onNodeWithTag("help_devices").performClick()
        scrollTo("help_content", "help_samsung")
        compose.onNodeWithTag("help_samsung").assertIsDisplayed()
        captureReview("help-$locale-${if (dark) "dark" else "light"}",
            "Help with fake state; Samsung/Xiaomi manual guidance, no system settings actually opened",
            compact = true, localeTag = locale, theme = if (dark) "dark" else "light")
        scrollTo("help_content", "help_xiaomi")
        compose.onNodeWithTag("help_xiaomi").assertIsDisplayed()
        scrollTo("help_content", "app_version")
        compose.onNodeWithTag("app_version").assertIsDisplayed()
        compose.onNodeWithText(BuildConfig.VERSION_NAME, substring = true).assertIsDisplayed()
        scrollTo("help_content", "help_connection_toggle")
        compose.onNodeWithTag("help_connection_toggle").performClick()
        scrollTo("help_content", "help_route_warnings")
        compose.onNodeWithTag("help_route_warnings").assertIsDisplayed()
        scrollTo("help_content", "help_media")
        compose.onNodeWithTag("help_media").assertIsDisplayed()
        scrollTo("help_content", "help_journal")
        compose.onNodeWithTag("help_journal").performClick()
        compose.onNodeWithTag("nav_2").assertIsSelected()
    }

    private fun openLinkDialog() {
        compose.onNodeWithTag("nav_1").performClick()
        scrollTo("routes_content", "import_link_routes")
        compose.onNodeWithTag("import_link_routes").performClick()
        compose.onNodeWithTag("link_dialog").assertExists()
    }

    private fun navLabelFitsMeasuredBounds(
        result: TextLayoutResult,
        measuredWidth: Float = result.size.width.toFloat(),
        measuredHeight: Float = result.size.height.toFloat(),
    ): Boolean {
        val length = result.layoutInput.text.length
        if (length == 0 || result.lineCount != 1 || result.isLineEllipsized(0) ||
            result.getLineStart(0) != 0 || result.getLineEnd(0, visibleEnd = true) != length ||
            result.getLineRight(0) - result.getLineLeft(0) > measuredWidth + 1f) return false
        return (0 until length).all { index ->
            val box = result.getBoundingBox(index)
            box.left >= -1f && box.top >= -1f &&
                box.right <= measuredWidth + 1f && box.bottom <= measuredHeight + 1f
        }
    }

    @Test fun updateHelpOffersCheckAndOptions() {
        var checks = 0
        var options = 0
        render(actions = TgProxyActions(onCheckUpdate = { checks++ }, onUpdateOptions = { _, _ -> options++ }))
        compose.onNodeWithTag("nav_3").performClick()
        scrollTo("help_content", "update_check")
        compose.onNodeWithTag("update_check").performClick()
        scrollTo("help_content", "update_auto_check")
        compose.onNodeWithTag("update_auto_check").performClick()
        scrollTo("help_content", "update_auto_download")
        compose.onNodeWithTag("update_auto_download").performClick()
        assertEquals(1, checks)
        assertEquals(2, options)
    }
    @Test fun updateOfferDownloadsButDoesNotInstallAutomatically() {
        var downloads = 0
        var installs = 0
        render(state = TgProxyUiState(update = io.github.byshadow64.tgproxy.UpdateUiState(
            phase = io.github.byshadow64.tgproxy.UpdatePhase.AVAILABLE, version = "0.1.7-dev", notes = "Test changes")),
            actions = TgProxyActions(onDownloadUpdate = { downloads++ }, onInstallUpdate = { installs++ }))
        scrollTo("overview_content", "update_download")
        compose.onNodeWithTag("update_download").performClick()
        compose.onNodeWithTag("update_install").assertDoesNotExist()
        assertEquals(1, downloads)
        assertEquals(0, installs)
    }
    @Test fun updateProgressExposesCancelAndNoInstall() {
        var cancels = 0
        render(state = TgProxyUiState(update = io.github.byshadow64.tgproxy.UpdateUiState(
            phase = io.github.byshadow64.tgproxy.UpdatePhase.DOWNLOADING, bytes = 25, total = 100)),
            actions = TgProxyActions(onCancelUpdate = { cancels++ }))
        scrollTo("overview_content", "update_cancel")
        compose.onNodeWithTag("update_cancel").performClick()
        compose.onNodeWithTag("update_install").assertDoesNotExist()
        assertEquals(1, cancels)
    }
    @Test fun updateReadyCompactRussianDark() = updateReadyCompact("ru", true)
    @Test fun updateReadyCompactEnglishLight() = updateReadyCompact("en", false)
    private fun updateReadyCompact(locale: String, dark: Boolean) {
        var installs = 0
        render(compact = true, localeTag = locale, dark = dark,
            state = TgProxyUiState(update = io.github.byshadow64.tgproxy.UpdateUiState(
                phase = io.github.byshadow64.tgproxy.UpdatePhase.READY, version = "0.1.7-dev", notes = "Update fixture")),
            actions = TgProxyActions(onInstallUpdate = { installs++ }))
        scrollTo("overview_content", "update_install")
        compose.onNodeWithTag("update_install").assertIsDisplayed().performClick()
        assertEquals(1, installs)
        captureReview("update-$locale", "Verified update ready; explicit install callback only", compact = true,
            theme = if (dark) "dark" else "light", localeTag = locale)
    }

    private fun render(
        state: TgProxyUiState = TgProxyUiState(),
        actions: TgProxyActions = TgProxyActions(),
        compact: Boolean = false,
        dark: Boolean? = null,
        localeTag: String? = null,
    ) {
        compose.setContent {
            val configuration = Configuration(LocalConfiguration.current).apply {
                if (localeTag != null) setLocale(Locale.forLanguageTag(localeTag))
                if (dark != null) {
                    uiMode = (uiMode and Configuration.UI_MODE_NIGHT_MASK.inv()) or
                        (if (dark) Configuration.UI_MODE_NIGHT_YES else Configuration.UI_MODE_NIGHT_NO)
                }
                if (compact) {
                    screenWidthDp = 320
                    screenHeightDp = 640
                }
            }
            val density = LocalDensity.current
            val context = LocalContext.current
            CompositionLocalProvider(
                LocalContext provides if (localeTag == null) context else context.createConfigurationContext(configuration),
                LocalConfiguration provides configuration,
                LocalDensity provides Density(density.density, if (compact) 1.3f else density.fontScale),
            ) {
                Box(if (compact) Modifier.requiredSize(320.dp, 640.dp) else Modifier.fillMaxSize()) {
                    TgProxyApp(state, actions)
                }
            }
        }
    }

    private fun scrollTo(containerTag: String, targetTag: String) {
        compose.onNodeWithTag(containerTag).performScrollToNode(hasTestTag(targetTag))
        compose.onNodeWithTag(targetTag).performScrollTo()
    }

    private fun assertNoLegacyHelperEditors() {
        for (tag in listOf("advanced_settings_toggle", "field_pairCode", "pair_helper", "field_pairHost_manual",
            "field_helperHost", "field_helperPort", "field_helperCertificateSha256", "field_helperToken")) {
            compose.onNodeWithTag(tag).assertDoesNotExist()
        }
    }

    private fun text(id: Int, localeTag: String? = null): String {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        if (localeTag == null) return context.getString(id)
        val configuration = Configuration(context.resources.configuration).apply {
            setLocale(Locale.forLanguageTag(localeTag))
        }
        return context.createConfigurationContext(configuration).getString(id)
    }

    /** Test artifacts are explicitly synthetic and never contain actual credentials. */
    private fun captureReview(
        name: String,
        scenario: String,
        theme: String = "device default",
        compact: Boolean = false,
        syntheticTokenMasked: Boolean = false,
        localeTag: String = "device default",
        targetTag: String? = null,
    ) {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val basename = "ui-review-$name"
        // Compose cannot capture Dialog windows below API28. The fallback is an
        // uncropped screenshot of this owned, synthetic test display, not a claim
        // that an API26 dialog-node capture succeeded.
        val fullDisplayFallback = targetTag != null && Build.VERSION.SDK_INT < 28
        val image = if (fullDisplayFallback) {
            requireNotNull(InstrumentationRegistry.getInstrumentation().uiAutomation.takeScreenshot()) {
                "The owned test display screenshot is unavailable"
            }
        } else {
            (if (targetTag == null) compose.onRoot() else compose.onNodeWithTag(targetTag)).captureToImage().asAndroidBitmap()
        }
        File(context.filesDir, "$basename.png").outputStream().use { output ->
            assertTrue("The fake UI screenshot must be saved", image.compress(Bitmap.CompressFormat.PNG, 100, output))
        }
        val metadata = JSONObject()
            .put("artifactType", "instrumented-fake-ui-snapshot")
            .put("source", "createComposeRule ComponentActivity; TgProxyApp with fake state and callbacks")
            .put("scenario", scenario)
            .put("fakeUiState", true)
            .put("realProxyServiceStarted", false)
            .put("networkUsed", false)
            .put("realCredentialsUsed", false)
            .put("syntheticTokenMasked", syntheticTokenMasked)
            .put("productionFlagSecureChanged", false)
            .put("theme", theme)
            .put("locale", localeTag)
            .put("viewportDp", if (compact) "320x640" else "device default")
            .put("fontScale", if (compact) "1.3" else "device default")
            .put("captureRequestedTarget", targetTag ?: "app root")
            .put("captureTarget", if (fullDisplayFallback) "entire owned synthetic test display" else targetTag ?: "app root")
            .put("captureMethod", if (fullDisplayFallback) "UiAutomation.takeScreenshot; uncropped API<28 fallback" else "Compose captureToImage")
            .put("imageWidthPixels", image.width)
            .put("imageHeightPixels", image.height)
        File(context.filesDir, "$basename.json").writeText(metadata.toString(2))
    }
}
