package io.github.byshadow64.tgproxy

import android.content.Context
import android.net.Uri
import io.github.byshadow64.tgproxy.core.*
import io.github.byshadow64.tgproxy.ui.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.time.LocalTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** Process-local state. It never persists logs, an active session or plaintext credentials. */
object AppRuntime {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutable = MutableStateFlow(TgProxyUiState(status = ProxyStatus.STARTING))
    val state = mutable.asStateFlow()
    private val ready = CompletableDeferred<Unit>()
    private val saveMutex = Mutex()
    private val ids = AtomicLong()
    private lateinit var context: Context
    private lateinit var store: SecureSettingsStore
    @Volatile private var saved: AppSettings? = null
    @Volatile private var applied: AppSettings? = null
    private var initialized = false
    private val eventTimes = mutableMapOf<String, Long>()
    @Volatile private var enrollmentCancel: AtomicBoolean? = null
    private val enrollmentGeneration = AtomicLong()
    private class PendingEnrollmentTask(val run: Long, val cancel: AtomicBoolean, val block: suspend () -> Unit) {
        val phase = AtomicInteger(0) // queued, claimed, running, complete, abandoned
    }
    @Volatile private var pendingEnrollmentTask: PendingEnrollmentTask? = null
    @Volatile private var registry: HelperRegistryClient? = null
    private val registryLock = Any()
    private val registryErrorTimes = mutableMapOf<RegistryFailureCode, Long>()
    private val sshGeneration = AtomicLong()
    @Volatile private var sshCancel: AtomicBoolean? = null
    @Volatile private var sshEndpoint: SshEndpoint? = null
    @Volatile private var sshKey: SshHostKey? = null
    @Volatile private var sshKeyConfirmed = false
    private class PendingSshTask(val run: Long, val block: suspend () -> Unit, val abandoned: () -> Unit) {
        val phase = AtomicInteger(0) // queued, claimed, running, complete, abandoned
    }
    @Volatile private var pendingSshTask: PendingSshTask? = null

    private fun enqueueEnrollment(cancel: AtomicBoolean, block: suspend () -> Unit) {
        val pending = PendingEnrollmentTask(enrollmentGeneration.incrementAndGet(), cancel, block)
        pendingEnrollmentTask = pending
        try {
            HelperEnrollmentService.start(context, pending.run)
            scope.launch {
                delay(5_000)
                if (pendingEnrollmentTask === pending && pending.phase.get() in 0..1) abandonEnrollment(pending.run)
            }
        } catch (_: Exception) { abandonEnrollment(pending.run) }
    }

    @Synchronized internal fun hasQueuedEnrollment(run: Long): Boolean =
        pendingEnrollmentTask?.let { it.run == run && it.phase.get() == 0 } == true

    @Synchronized internal fun takeEnrollment(run: Long): (suspend () -> Unit)? {
        val pending = pendingEnrollmentTask ?: return null
        if (pending.run != run || !pending.phase.compareAndSet(0, 1)) return null
        return task@ {
            if (!pending.phase.compareAndSet(1, 2)) return@task
            try { pending.block() }
            finally {
                pending.phase.set(3)
                synchronized(this) {
                    if (pendingEnrollmentTask === pending) {
                        pendingEnrollmentTask = null
                        if (enrollmentCancel === pending.cancel) enrollmentCancel = null
                        mutable.update { it.copy(isSaving = false) }
                    }
                }
            }
        }
    }

    @Synchronized internal fun cancelEnrollment(run: Long) {
        pendingEnrollmentTask?.takeIf { it.run == run }?.cancel?.set(true)
    }

    @Synchronized internal fun abandonEnrollment(run: Long) {
        val pending = pendingEnrollmentTask?.takeIf { it.run == run } ?: return
        pending.cancel.set(true)
        val phase = pending.phase.get()
        if (phase in 0..1 && pending.phase.compareAndSet(phase, 4)) {
            pendingEnrollmentTask = null
            if (enrollmentCancel === pending.cancel) enrollmentCancel = null
            mutable.update { it.copy(isSaving = false, pairingStatus = PairingStatus.ERROR,
                pairingMessage = text(R.string.service_registry_cancelled), registrySetupRequired = false) }
        }
    }

    private fun enqueueSshTask(run: Long, abandoned: () -> Unit = {}, block: suspend () -> Unit) {
        val pending = PendingSshTask(run, block, abandoned)
        pendingSshTask = pending
        try {
            HelperSetupService.start(context, run)
            scope.launch {
                delay(5_000)
                if (pendingSshTask === pending && pending.phase.get() in 0..1) abandonSshTask(run)
            }
        }
        catch (_: Exception) {
            abandonSshTask(run)
            finishSshFailure(run, SshFailureCode.CONNECTION_FAILED)
        }
    }

    /** Only the private foreground service can claim a user-created, process-memory task. */
    @Synchronized internal fun hasQueuedSshTask(run: Long): Boolean = pendingSshTask?.let { it.run == run && it.phase.get() == 0 } == true

    @Synchronized internal fun takeSshTask(run: Long): (suspend () -> Unit)? {
        val pending = pendingSshTask ?: return null
        if (pending.run != run || !pending.phase.compareAndSet(0, 1)) return null
        return task@ {
            if (!pending.phase.compareAndSet(1, 2)) return@task
            try { pending.block() }
            finally {
                pending.phase.set(3); pending.abandoned()
                if (pendingSshTask === pending) pendingSshTask = null
                if (run == sshGeneration.get()) {
                    sshCancel = null; sshKeyConfirmed = false
                    mutable.update { it.copy(isSaving = false) }
                }
            }
        }
    }

    @Synchronized internal fun abandonSshTask(run: Long) {
        val pending = pendingSshTask ?: return
        if (pending.run != run) return
        cancelHelperSsh(run)
        val phase = pending.phase.get()
        if (phase in 0..1 && pending.phase.compareAndSet(phase, 4)) {
            pending.abandoned(); pendingSshTask = null
            if (run == sshGeneration.get()) {
                sshCancel = null; sshKeyConfirmed = false
                finishSshFailure(run, SshFailureCode.CANCELLED)
                mutable.update { it.copy(isSaving = false) }
            }
        }
    }

    private fun registryClient(): HelperRegistryClient = registry ?: synchronized(registryLock) {
        registry ?: HelperRegistryClient(HttpsRegistryTransport(HelperRegistryConfig.BASE_URL),
            HelperRegistryConfig.signingPublicKey(), RegistryDeviceIdentityProvider()).also { registry = it }
    }

    /** Called for each new Helper socket; existing transports keep their established connection. */
    fun helperConnectionProvider(snapshot: AppSettings): HelperConnectionProvider? {
        if (!snapshot.helperEnabled || !snapshot.helperRegistryManaged) return null
        return HelperConnectionProvider { cancelled ->
            try { registryClient().lease(snapshot.helperHost, cancelled = cancelled).settings() }
            catch (e: RegistryException) {
                // An individual Telegram socket closing is not a cancelled user enrollment.
                if (e.code == RegistryFailureCode.CANCELLED) throw e
                synchronized(registryErrorTimes) {
                    val now = System.nanoTime()
                    if (now - (registryErrorTimes[e.code] ?: 0L) >= 1_000_000_000L) {
                        registryErrorTimes[e.code] = now
                        append(LogLevel.WARNING, registryMessage(e.code))
                    }
                }
                throw e
            }
        }
    }

    private fun registryMessage(code: RegistryFailureCode) = text(when (code) {
        RegistryFailureCode.INVALID_ADDRESS -> R.string.service_registry_address
        RegistryFailureCode.UNKNOWN_HELPER -> R.string.service_registry_unknown
        RegistryFailureCode.DEVICE_DENIED -> R.string.service_registry_denied
        RegistryFailureCode.RATE_LIMITED -> R.string.service_registry_rate_limited
        RegistryFailureCode.CANCELLED -> R.string.service_registry_cancelled
        RegistryFailureCode.TIMEOUT -> R.string.service_registry_timeout
        else -> R.string.service_registry_failed
    })

    @Synchronized fun initialize(ctx: Context) {
        if (initialized) return
        initialized = true
        context = ctx.applicationContext
        store = SecureSettingsStore(context)
        scope.launch {
            try {
                val s = store.load() ?: AppSettings.fresh().also { store.save(it) }
                saved = s
                mutable.update { it.copy(settings = s.ui(), status = ProxyStatus.STOPPED, hasSavedSettings = true) }
                ready.complete(Unit)
            } catch (_: Exception) {
                mutable.update { it.copy(status = ProxyStatus.ERROR, statusMessage = text(R.string.service_store_error)) }
                ready.completeExceptionally(StoreException())
            }
        }
    }
    private fun text(id: Int) = context.getString(id)
    suspend fun settings(): AppSettings { ready.await(); return saved ?: throw StoreException() }
    fun setStatus(status: ProxyStatus, message: String? = null) { mutable.update { it.copy(status = status,
        statusMessage = message, runningPort = if (status == ProxyStatus.RUNNING) it.runningPort else null) } }
    fun showMessage(id: Int) { mutable.update { it.copy(statusMessage = text(id)) } }
    fun running(settings: AppSettings) { applied = settings; mutable.update { it.copy(status = ProxyStatus.RUNNING,
        statusMessage = null, runningPort = settings.port) } }
    fun stopped() { applied = null; mutable.update { it.copy(status = ProxyStatus.STOPPED, statusMessage = null,
        runningPort = null, metrics = it.metrics.copy(activeConnections = 0)) } }
    fun metrics(s: EngineStats) { mutable.update { it.copy(metrics = UiMetrics(s.activeConnections, s.bytesDown, s.bytesUp,
        s.directConnections + s.relayConnections, s.helperConnections)) } }
    fun failure(code: EngineFailureCode?) {
        applied = null
        val message = text(if (code == EngineFailureCode.PORT_UNAVAILABLE) R.string.service_port_busy else R.string.service_start_error)
        setStatus(ProxyStatus.ERROR, message)
        append(LogLevel.ERROR, message)
    }
    fun append(level: LogLevel, message: String) {
        val entry = JournalEntry(ids.incrementAndGet(), LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")), level, message)
        mutable.update { it.copy(journal = (it.journal.takeLast(199) + entry)) }
    }
    fun event(e: EngineEvent) {
        // Prevent a local client flood from producing unbounded UI update work.
        synchronized(eventTimes) {
            val now = System.nanoTime()
            // Fixed route enums/DC/media keep this key space bounded while distinguishing cold routes.
            val key = if (e.handshakeFailure != null) "${e.code}:${e.handshakeFailure}" else if (e.routeStrategy != null || e.code == EventCode.ROUTE_CONNECTED)
                "${e.code}:${e.dc}:${e.media}:${e.routeStrategy}:${e.relayCatalogIndex}:${e.stage}" else e.code.name
            if (e.code !in setOf(EventCode.STARTED, EventCode.STOPPED) && now - (eventTimes[key] ?: 0L) < 1_000_000_000L) return
            eventTimes[key] = now
        }
        val id = when (e.code) {
            EventCode.STARTED -> R.string.event_started
            EventCode.STOPPED -> R.string.event_stopped
            EventCode.CONNECTION_OPENED -> R.string.event_connection_opened
            EventCode.ROUTE_CONNECTED -> when (e.route) {
                RouteKind.HELPER_TLS -> R.string.event_helper_connected
                RouteKind.RELAY_WSS -> R.string.event_relay_connected
                else -> R.string.event_direct_connected
            }
            EventCode.CONNECTION_CLOSED -> R.string.event_connection_closed
            EventCode.CONNECTION_LIMIT -> R.string.event_connection_limit
            EventCode.INVALID_HANDSHAKE -> R.string.event_invalid_handshake
            EventCode.UNSUPPORTED_DC -> R.string.event_unsupported_dc
            EventCode.ROUTE_ATTEMPT_FAILED -> R.string.event_route_attempt_failed
            EventCode.UPSTREAM_UNAVAILABLE -> R.string.event_unavailable
            EventCode.HELPER_PIN_MISMATCH -> R.string.event_pin_mismatch
            EventCode.HELPER_REJECTED -> R.string.event_helper_rejected
            EventCode.PROTOCOL_ERROR -> R.string.event_protocol_error
            EventCode.TIMEOUT -> when (e.stage) {
                EngineStage.FIRST_REPLY -> R.string.event_first_reply_timeout
                EngineStage.CLIENT_HANDSHAKE -> R.string.event_client_timeout
                EngineStage.FRAME_PROGRESS -> R.string.event_frame_timeout
                else -> R.string.event_timeout
            }
        }
        val level = when (e.code) {
            EventCode.HELPER_PIN_MISMATCH, EventCode.HELPER_REJECTED, EventCode.PROTOCOL_ERROR -> LogLevel.ERROR
            EventCode.CONNECTION_LIMIT, EventCode.INVALID_HANDSHAKE, EventCode.UNSUPPORTED_DC, EventCode.UPSTREAM_UNAVAILABLE, EventCode.TIMEOUT -> LogLevel.WARNING
            else -> LogLevel.INFO
        }
        val handshakeDetail = e.handshakeFailure?.let { reason -> text(when (reason) {
            HandshakeFailure.INVALID_LENGTH -> R.string.event_handshake_length
            HandshakeFailure.SECRET_OR_PROTOCOL -> R.string.event_handshake_secret
            HandshakeFailure.ZERO_DC -> R.string.event_handshake_zero_dc
            HandshakeFailure.RESERVED_DC -> R.string.event_handshake_reserved_dc
        }) } ?: ""
        val routeDetail = e.routeStrategy?.let {
            " · $it · media=${e.media}" + (e.relayCatalogIndex?.let { index -> " · relay=$index" } ?: "")
        } ?: ""
        append(level, text(id) + handshakeDetail + (e.dc?.let { " · DC $it" } ?: "") + routeDetail + (e.stage?.let { " · $it" } ?: ""))
    }
    @Synchronized fun save(ui: ProxySettingsUi, onRestart: (() -> Unit)? = null) {
        if (!canStart()) return
        mutable.update { it.copy(isSaving = true) }
        scope.launch {
            var persisted = false
            try {
                saveMutex.withLock {
                    val previous = settings()
                    val validation = SettingsValidation.parse(ui, previous)
                    if (validation.settings == null) {
                        val errors = validation.errors.mapValues { (_, code) -> text(when (code) {
                            "port" -> R.string.service_validation_port
                            "host" -> R.string.service_validation_host
                            "pin" -> R.string.service_validation_pin
                            else -> R.string.service_validation_token
                        }) }
                        mutable.update { it.copy(validationErrors = errors, statusMessage = text(R.string.service_validation_failed)) }
                        return@withLock
                    }
                    store.save(validation.settings)
                    saved = validation.settings
                    mutable.update { it.copy(settings = validation.settings.ui(), validationErrors = emptyMap(), hasSavedSettings = true,
                        statusMessage = text(if (it.status == ProxyStatus.RUNNING) R.string.service_saved_restart else R.string.service_saved)) }
                    append(LogLevel.INFO, text(R.string.service_saved))
                    persisted = true
                }
            } catch (_: Exception) { showMessage(R.string.service_store_error) }
            finally {
                // The Activity's restart action uses canStart(). Clear the completed save
                // before invoking it, on the same UI turn, and after releasing saveMutex.
                withContext(Dispatchers.Main) {
                    mutable.update { it.copy(isSaving = false) }
                    if (persisted) onRestart?.invoke()
                }
            }
        }
    }
    /** Enrollment never runs against a live engine and never saves unverified fields. */
    @Synchronized fun connectHelperIp(input: String) {
        val current = mutable.value
        if (current.isSaving || current.pairingStatus == PairingStatus.CONNECTING || current.status !in setOf(ProxyStatus.STOPPED, ProxyStatus.ERROR)) return
        val host = try { HelperRegistryClient.numericIp(input) } catch (_: RegistryException) {
            mutable.update { it.copy(pairingStatus = PairingStatus.ERROR, pairingMessage = null,
                pairingValidationErrors = mapOf(PairingFields.HOST to text(R.string.service_registry_address)), registrySetupRequired = false) }
            return
        }
        val cancel = AtomicBoolean(false); enrollmentCancel = cancel
        mutable.update { it.copy(isSaving = true, pairingStatus = PairingStatus.CONNECTING, pairingMessage = null,
            pairingValidationErrors = emptyMap(), registrySetupRequired = false) }
        enqueueEnrollment(cancel) {
            try {
                saveMutex.withLock {
                    if (cancel.get()) throw RegistryException(RegistryFailureCode.CANCELLED)
                    val previous = settings()
                    val verified = registryClient().lease(host, forceRefresh = true) { cancel.get() }
                    if (cancel.get()) throw RegistryException(RegistryFailureCode.CANCELLED)
                    // Persist only the verified endpoint and a mode flag, never a bearer lease.
                    val next = AppSettings(previous.port, previous.secretHex, true, verified.ip, verified.port,
                        verified.fingerprintHex, "", helperRegistryManaged = true)
                    store.save(next)
                    saved = next
                    mutable.update { it.copy(settings = next.ui(), hasSavedSettings = true, validationErrors = emptyMap(),
                        pairingStatus = PairingStatus.SUCCESS, pairingMessage = text(R.string.service_registry_success),
                        pairingValidationErrors = emptyMap(), registrySetupRequired = false) }
                    append(LogLevel.INFO, text(R.string.service_registry_success))
                }
            } catch (e: RegistryException) {
                val message = registryMessage(e.code)
                mutable.update { it.copy(pairingStatus = PairingStatus.ERROR, pairingMessage = message,
                    registrySetupRequired = e.code == RegistryFailureCode.UNKNOWN_HELPER) }
                append(LogLevel.WARNING, message)
            } catch (_: Exception) {
                mutable.update { it.copy(pairingStatus = PairingStatus.ERROR,
                    pairingMessage = text(if (cancel.get()) R.string.service_registry_cancelled else R.string.service_registry_failed), registrySetupRequired = false) }
            }
        }
    }
    fun cancelHelperConnect() { enrollmentCancel?.set(true) }

    @Synchronized fun probeHelperSsh(host: String, port: String, user: String) {
        if (mutable.value.isSaving || mutable.value.status !in setOf(ProxyStatus.STOPPED, ProxyStatus.ERROR)) return
        val endpoint = try {
            val ip = HelperRegistryClient.numericIp(host)
            val number = port.toInt(); require(number in 1..65535 && user.matches(Regex("[A-Za-z_][A-Za-z0-9_.-]{0,31}")))
            SshEndpoint(ip, number, user)
        } catch (_: Exception) {
            mutable.update { it.copy(sshSetup = SshSetupUiState(phase = SshSetupPhase.ERROR, progressMessage = text(R.string.ssh_invalid_input))) }
            return
        }
        sshEndpoint = null; sshKey = null; sshKeyConfirmed = false
        val run = sshGeneration.incrementAndGet(); val cancel = AtomicBoolean(false); sshCancel = cancel
        mutable.update { it.copy(isSaving = true, sshSetup = SshSetupUiState(SshSetupPhase.PROBING, endpoint.ip,
            endpoint.port, endpoint.username, progressMessage = text(R.string.ssh_connecting))) }
        enqueueSshTask(run) {
            try {
                val observed = SshHelperInstaller.preflight(endpoint, cancelled = { cancel.get() })
                if (cancel.get()) throw SshException(SshFailureCode.CANCELLED)
                if (run != sshGeneration.get()) return@enqueueSshTask
                sshEndpoint = endpoint; sshKey = observed
                mutable.update { it.copy(sshSetup = it.sshSetup.copy(phase = SshSetupPhase.CONFIRM_HOST_KEY,
                    keyType = observed.keyType, fingerprint = observed.sha256Fingerprint, progressMessage = text(R.string.ssh_key_ready))) }
            } catch (e: SshException) { finishSshFailure(run, e.code) }
            catch (_: Exception) { finishSshFailure(run, if (cancel.get()) SshFailureCode.CANCELLED else SshFailureCode.CONNECTION_FAILED) }
        }
    }

    @Synchronized fun confirmHelperSshKey() {
        if (mutable.value.isSaving || mutable.value.sshSetup.phase != SshSetupPhase.CONFIRM_HOST_KEY || sshEndpoint == null || sshKey == null) return
        sshKeyConfirmed = true
        mutable.update { it.copy(sshSetup = it.sshSetup.copy(phase = SshSetupPhase.READY, progressMessage = null)) }
    }

    @Synchronized fun deployHelperSsh(password: CharArray, allowRegisteredDevices: Boolean, allowExistingUpgrade: Boolean) {
        val endpoint = sshEndpoint; val accepted = sshKey
        if (mutable.value.isSaving || mutable.value.sshSetup.phase != SshSetupPhase.READY || !sshKeyConfirmed ||
            endpoint == null || accepted == null || !allowRegisteredDevices || mutable.value.status !in setOf(ProxyStatus.STOPPED, ProxyStatus.ERROR)) {
            password.fill('\u0000'); return
        }
        val input = password.copyOf(); password.fill('\u0000')
        val run = sshGeneration.incrementAndGet(); val cancel = AtomicBoolean(false); sshCancel = cancel
        mutable.update { it.copy(isSaving = true, sshSetup = it.sshSetup.copy(phase = SshSetupPhase.DEPLOYING,
            progressMessage = text(R.string.ssh_connecting), percent = null)) }
        enqueueSshTask(run, abandoned = { input.fill('\u0000') }) {
            try {
                settings() // Do not change a server if the saved local profile cannot be opened.
                val payload = HelperPayloadAssets.load(context.assets)
                val options = SshInstallOptions(HelperRegistryConfig.BASE_URL, HelperRegistryConfig.SIGNING_PUBLIC_KEY_SPKI,
                    endpoint.ip, allowRegisteredDevices = true, allowExistingPrivateUpgrade = allowExistingUpgrade)
                val installed = SshHelperInstaller.deploy(endpoint, input, accepted, payload, options, cancelled = { cancel.get() }, progress = { event ->
                    if (run == sshGeneration.get()) {
                        val message = when (event.stage) {
                            SshInstallStage.UPLOADING -> R.string.ssh_uploading
                            SshInstallStage.INSTALLING -> R.string.ssh_installing
                            SshInstallStage.VERIFYING_RESULT, SshInstallStage.COMPLETE -> R.string.ssh_verifying
                            else -> R.string.ssh_connecting
                        }
                        val percent = if (event.stage == SshInstallStage.UPLOADING && event.totalBytes > 0)
                            ((event.sentBytes.coerceIn(0, event.totalBytes) * 100) / event.totalBytes).toInt() else null
                        mutable.update { it.copy(sshSetup = it.sshSetup.copy(progressMessage = text(message), percent = percent)) }
                    }
                })
                if (cancel.get()) throw SshException(SshFailureCode.CANCELLED)
                if (run != sshGeneration.get()) return@enqueueSshTask
                mutable.update { it.copy(sshSetup = it.sshSetup.copy(phase = SshSetupPhase.VERIFYING, progressMessage = text(R.string.ssh_verifying), percent = null)) }
                val verified = registryClient().lease(endpoint.ip, forceRefresh = true) { cancel.get() }
                if (cancel.get()) throw SshException(SshFailureCode.CANCELLED)
                if (installed.host != verified.ip || installed.port != verified.port || installed.fingerprintHex != verified.fingerprintHex || installed.helperId != verified.helperId)
                    throw SshException(SshFailureCode.UNVERIFIED_RESULT)
                saveMutex.withLock {
                    if (run != sshGeneration.get() || cancel.get()) throw SshException(SshFailureCode.CANCELLED)
                    val previous = settings()
                    val next = AppSettings(previous.port, previous.secretHex, true, verified.ip, verified.port, verified.fingerprintHex, "", true)
                    store.save(next); saved = next
                    mutable.update { it.copy(settings = next.ui(), hasSavedSettings = true, validationErrors = emptyMap(), registrySetupRequired = false,
                        pairingStatus = PairingStatus.SUCCESS, pairingMessage = text(R.string.ssh_success), pairingValidationErrors = emptyMap(),
                        sshSetup = it.sshSetup.copy(phase = SshSetupPhase.SUCCESS, progressMessage = text(R.string.ssh_success))) }
                    append(LogLevel.INFO, text(R.string.ssh_success))
                }
            } catch (e: SshException) { finishSshFailure(run, e.code) }
            catch (e: RegistryException) {
                if (e.code == RegistryFailureCode.CANCELLED) finishSshFailure(run, SshFailureCode.CANCELLED)
                else if (run == sshGeneration.get()) mutable.update { it.copy(sshSetup = it.sshSetup.copy(phase = SshSetupPhase.ERROR,
                    progressMessage = text(R.string.ssh_registry_unverified), percent = null)) }
            } catch (_: Exception) { finishSshFailure(run, if (cancel.get()) SshFailureCode.CANCELLED else SshFailureCode.INVALID_PAYLOAD) }
            finally {
                input.fill('\u0000')
            }
        }
    }

    private fun finishSshFailure(run: Long, code: SshFailureCode) {
        if (run != sshGeneration.get()) return
        val id = when (code) {
            SshFailureCode.CANCELLED -> R.string.ssh_cancelled
            SshFailureCode.HOST_KEY_CHANGED -> R.string.ssh_key_changed
            SshFailureCode.INVALID_REQUEST -> R.string.ssh_invalid_input
            SshFailureCode.ROOT_REQUIRED -> R.string.ssh_root_required
            else -> R.string.ssh_failed
        }
        mutable.update { it.copy(sshSetup = it.sshSetup.copy(phase = if (code == SshFailureCode.CANCELLED) SshSetupPhase.CANCELLED else SshSetupPhase.ERROR,
            progressMessage = text(id), percent = null)) }
        append(LogLevel.WARNING, text(id))
    }

    fun cancelHelperSsh(expectedRun: Long? = null) { if (expectedRun == null || expectedRun == sshGeneration.get()) sshCancel?.set(true) }
    @Synchronized fun resetHelperSsh() {
        if (mutable.value.isSaving) return
        sshGeneration.incrementAndGet(); sshEndpoint = null; sshKey = null; sshKeyConfirmed = false
        mutable.update { it.copy(sshSetup = SshSetupUiState()) }
    }

    @Synchronized fun pairHelper(host: String, code: String) {
        val current = mutable.value
        if (current.isSaving || current.pairingStatus == PairingStatus.CONNECTING || current.status !in setOf(ProxyStatus.STOPPED, ProxyStatus.ERROR)) return
        val errors = mutableMapOf<String, String>()
        try { HelperPairingClient.endpoint(host) } catch (_: PairingException) { errors[PairingFields.HOST] = text(R.string.service_pair_address) }
        if (!Regex("TG1\\.[A-Za-z0-9_-]{11}\\.[A-Za-z0-9_-]{22}").matches(code.trim())) errors[PairingFields.CODE] = text(R.string.service_pair_code)
        if (errors.isNotEmpty()) {
            mutable.update { it.copy(pairingStatus = PairingStatus.ERROR, pairingMessage = null, pairingValidationErrors = errors) }
            return
        }
        val cancel = AtomicBoolean(false); enrollmentCancel = cancel
        mutable.update { it.copy(isSaving = true, pairingStatus = PairingStatus.CONNECTING, pairingMessage = null, pairingValidationErrors = emptyMap(), registrySetupRequired = false) }
        enqueueEnrollment(cancel) {
            try {
                saveMutex.withLock {
                    if (cancel.get()) throw PairingException(PairingFailureCode.CANCELLED)
                    val previous = settings()
                    val paired = HelperPairingClient.pair(host, code, cancelled = { cancel.get() })
                    if (cancel.get()) throw PairingException(PairingFailureCode.CANCELLED)
                    val next = AppSettings(port = previous.port, secretHex = previous.secretHex, helperEnabled = true, helperHost = paired.host, helperPort = paired.port,
                        helperFingerprint = paired.fingerprintHex, helperToken = paired.token)
                    store.save(next)
                    saved = next
                    mutable.update { it.copy(settings = next.ui(), hasSavedSettings = true, validationErrors = emptyMap(),
                        pairingStatus = PairingStatus.SUCCESS, pairingMessage = text(R.string.service_pair_success), pairingValidationErrors = emptyMap()) }
                    append(LogLevel.INFO, text(R.string.service_pair_success))
                }
            } catch (e: PairingException) {
                val message = text(when (e.code) {
                    PairingFailureCode.INVALID_ADDRESS -> R.string.service_pair_address
                    PairingFailureCode.INVALID_CODE -> R.string.service_pair_code
                    PairingFailureCode.TIMEOUT -> R.string.service_pair_timeout
                    PairingFailureCode.CANCELLED -> R.string.service_pair_cancelled
                    else -> R.string.service_pair_failed
                })
                mutable.update { it.copy(pairingStatus = PairingStatus.ERROR, pairingMessage = message) }
                append(LogLevel.WARNING, message)
            } catch (_: Exception) {
                mutable.update { it.copy(pairingStatus = PairingStatus.ERROR,
                    pairingMessage = text(if (cancel.get()) R.string.service_pair_cancelled else R.string.service_store_error)) }
            }
        }
    }
    fun canStart(): Boolean = mutable.value.let { !it.isSaving && it.pairingStatus != PairingStatus.CONNECTING &&
        it.sshSetup.phase !in setOf(SshSetupPhase.PROBING, SshSetupPhase.DEPLOYING, SshSetupPhase.VERIFYING) }
    fun telegramUri(web: Boolean = false): Uri? {
        val s = applied ?: return null
        if (mutable.value.status != ProxyStatus.RUNNING) return null
        val builder = if (web) Uri.Builder().scheme("https").authority("t.me").path("/proxy")
            else Uri.Builder().scheme("tg").authority("proxy")
        return builder.appendQueryParameter("server", "127.0.0.1")
            .appendQueryParameter("port", s.port.toString()).appendQueryParameter("secret", "dd" + s.secretHex).build()
    }
    fun clearJournal() { mutable.update { it.copy(journal = emptyList()) } }
    fun journalReport(): String = "TG Proxy Android ${BuildConfig.VERSION_NAME}\n" + mutable.value.journal.joinToString("\n") { "${it.timestamp} ${it.level} ${it.message}" }
}
