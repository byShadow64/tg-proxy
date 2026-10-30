package io.github.byshadow64.tgproxy.core

/** Relay admission, not a device firewall or inspection of encrypted MTProto message content. */
internal object TelegramRelayPolicy {
    private val supportedDcs = setOf(1, 2, 3, 4, 5, 203)
    private val helperDomains = (1..5).flatMap { dc ->
        listOf("kws$dc.web.telegram.org", "kws$dc-1.web.telegram.org")
    }.toSet()

    fun supportsDc(dc: Int): Boolean = dc in supportedDcs

    fun requireDc(dc: Int) {
        if (!supportsDc(dc)) throw ProtocolException()
    }

    fun officialDomain(dc: Int, media: Boolean): String {
        requireDc(dc)
        val officialDc = if (dc == 203) 2 else dc
        return "kws$officialDc${if (media) "-1" else ""}.web.telegram.org"
    }

    /** Exact catalog match, before TLS, credentials or any network side effect. */
    fun requireHelperDomain(domain: String) {
        if (domain !in helperDomains) throw ProtocolException()
    }
}
