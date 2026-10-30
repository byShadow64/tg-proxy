package io.github.byshadow64.tgproxy

import java.util.Base64

/** Public registry location and independently provisioned signing key; neither is an owner credential. */
object HelperRegistryConfig {
    const val BASE_URL = "https://217.177.34.28"
    const val SIGNING_PUBLIC_KEY_SPKI = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7Ee8jsSwimvZ4tmWVRcIWG90IjpDCkTy2O6bN6yDi-F5x8XU0PVndRntC4IHhygdW22EJqhywQUZSQeZJQ_gqA"
    fun signingPublicKey(): ByteArray = Base64.getUrlDecoder().decode(SIGNING_PUBLIC_KEY_SPKI)
}
