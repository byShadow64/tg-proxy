package io.github.byshadow64.tgproxy.core

/**
 * Public hostnames from the MIT Flowseal/byShadow64 desktop catalog proxy/config.py,
 * last source-file commit 7e7d7ae3f84d19c43e045eb36555e5275cf79494
 * (file SHA-256 c120cb21a91ea708dd2baf4f4a29a5a08caea43e1cad37650d79a7b2fe7f59f1).
 * No source or assets from the GPL Android reference are included.
 * This offline list uses authenticated WSS/443, never the reference's HTTP/80 option.
 */
internal object WssRelayCatalog {
    val domains = listOf("cakeisalie.co.uk", "offshor.co.uk", "pclead.co.uk", "sorokdva.co.uk")
}
