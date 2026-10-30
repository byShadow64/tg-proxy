package io.github.byshadow64.tgproxy.core

/** Configuration is a snapshot. Credentials are deliberately absent from toString(). */
class HelperSettings(
    val host: String,
    val port: Int = 8444,
    val fingerprintHex: String,
    val token: String,
) {
    override fun toString() = "HelperSettings(<private>)"
}

/** Fresh lease for a new Helper connection only. Implementations must observe cancellation promptly. */
fun interface HelperConnectionProvider { fun settings(cancelled: () -> Boolean): HelperSettings }

class EngineConfig(
    val port: Int = 1443,
    val secretHex: String,
    val helper: HelperSettings? = null,
    val maxConnections: Int = 32,
) {
    override fun toString() = "EngineConfig(port=$port, maxConnections=$maxConnections)"
}

enum class EngineState { STOPPED, RUNNING }
enum class RouteKind { DIRECT_WSS, RELAY_WSS, HELPER_TLS }
/** Fixed public diagnostic labels; these never contain hostnames, account data or credentials. */
enum class RouteStrategy { OFFICIAL_DNS, FIXED_IP, FRONTED_IP, RELAY_WSS }
/** Parser categories only; no decrypted bytes, secret values or guessed client identity. */
enum class HandshakeFailure { INVALID_LENGTH, SECRET_OR_PROTOCOL, ZERO_DC, RESERVED_DC }
enum class EngineStage { CLIENT_HANDSHAKE, DNS, CONNECT, TLS, WEBSOCKET_HANDSHAKE, HELPER_AUTH, FIRST_REPLY, FRAME_PROGRESS, WRITE }
enum class EventCode {
    STARTED, STOPPED, CONNECTION_OPENED, ROUTE_CONNECTED, CONNECTION_CLOSED,
    /** One candidate failed; other routes may still connect. This is not a session failure. */
    ROUTE_ATTEMPT_FAILED,
    CONNECTION_LIMIT, INVALID_HANDSHAKE, UNSUPPORTED_DC, UPSTREAM_UNAVAILABLE,
    HELPER_PIN_MISMATCH, HELPER_REJECTED, PROTOCOL_ERROR, TIMEOUT,
}

/** Safe structured events: never include credentials, payloads, hostnames or exceptions. */
data class EngineEvent(
    val code: EventCode,
    val activeConnections: Int = 0,
    val dc: Int? = null,
    val media: Boolean = false,
    val route: RouteKind? = null,
    val stage: EngineStage? = null,
    val routeStrategy: RouteStrategy? = null,
    val relayCatalogIndex: Int? = null,
    val handshakeFailure: HandshakeFailure? = null,
)

data class EngineStats(
    val state: EngineState = EngineState.STOPPED,
    val port: Int = 0,
    val activeConnections: Int = 0,
    val totalConnections: Long = 0,
    val bytesUp: Long = 0,
    val bytesDown: Long = 0,
    val directConnections: Long = 0,
    val helperConnections: Long = 0,
    val relayConnections: Long = 0,
)

/** Public failures have fixed messages so UI can display a code without leaking input. */
enum class EngineFailureCode { INVALID_CONFIGURATION, PORT_UNAVAILABLE, ALREADY_RUNNING }
class EngineException(val code: EngineFailureCode) : Exception(code.name)
