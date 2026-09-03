package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata

/**
 * What the SDK will accept when discovering issuer and authorization server metadata.
 *
 * Kept in one place so a rule can be tightened or relaxed without touching the resolution logic.
 * [Default] preserves the SDK's existing, permissive reach; [Strict] is what OpenID4VCI 1.0
 * actually requires.
 *
 * Every non-spec allowance [Default] grants is load-bearing for a real issuer. Against the EBSI
 * conformance mocks the spec's own URL form returns 404, the metadata is draft-shaped, and the
 * `oauth-authorization-server` location returns 404 -- so [Strict] would break that issuer on
 * three separate switches. [Strict] is for conformance testing, not for a wallet.
 */
data class DiscoveryPolicy(

    /**
     * Schemes accepted for metadata retrieval.
     *
     * OpenID4VCI 1.0 section 12.2.2: "Communication with the Credential Issuer Metadata Endpoint
     * MUST utilize TLS". `http` is kept by default because issuers are commonly run locally
     * during development. This also closes `file:`, `ftp:` and `jar:`, which the previous check
     * accepted because it only asked whether `java.net.URL` could parse the string.
     */
    val allowedSchemes: Set<String> = setOf("https", "http"),

    /**
     * Fall back to `<identifier>/.well-known/...` when the spec's insertion form yields nothing.
     *
     * Not in the spec: section 12.2.2 requires the well-known string be inserted *between the host
     * and the path*. Kept on because issuers that only serve the suffix form are common.
     */
    val allowSuffixWellKnownFallback: Boolean = true,

    /**
     * Try `openid-configuration` when `oauth-authorization-server` yields nothing.
     *
     * Not in OpenID4VCI, which names only the RFC 8414 location. Kept on because authorization
     * servers fronted by an OpenID Provider commonly publish only the OpenID Connect Discovery
     * document.
     */
    val allowOpenIdConfigurationFallback: Boolean = true,

    /**
     * Reject a document whose `credential_issuer` differs from the identifier it was fetched for.
     *
     * OpenID4VCI 1.0 section 12.2.4: if the values are not identical "the data contained in the
     * response MUST NOT be used".
     *
     * **Off by default**, because real deployments do not satisfy it yet. The iGrant issuers serve
     * their metadata at both `<base>/service` and `<base>/service/version-01` while always
     * declaring the latter, and the wallet asks using the former, so enforcing this rejects a
     * working production issuer. A mismatch is logged either way, so the gap stays visible.
     *
     * Turn it on once issuers are asked for their canonical identifier: it is the check that stops
     * a redirect or a misconfigured tenant substituting another issuer's endpoints.
     */
    val requireIssuerIdentifierMatch: Boolean = false,

    /** Accept pre-1.0 draft issuer metadata. Set false to require OpenID4VCI 1.0. */
    val allowDraftMetadata: Boolean = true,

    /**
     * Reject a document whose `Content-Type` is not JSON.
     *
     * Section 12.2.2 requires the issuer to declare the media type, but issuers that serve correct
     * JSON under `text/plain` are common enough that enforcing it by default would cost more than
     * it gains. A JWT is routed to the signature verifier regardless of this flag.
     */
    val requireJsonContentType: Boolean = false,

    /** Send an `Accept-Language` header derived from the device locale (RECOMMENDED, 12.2.2). */
    val sendAcceptLanguage: Boolean = true,

    /** Overrides the device locale for `Accept-Language`. Null derives it from the default locale. */
    val acceptLanguage: String? = null,

    /**
     * Largest metadata document accepted, in bytes. `null` (the default) means no size check is
     * applied.
     *
     * Off by default: real issuer metadata -- especially `credential_configurations_supported`
     * entries with embedded base64 `display` logos -- can legitimately run well past a few hundred
     * KB, and there is no size the SDK can pick that is safe for every issuer. Set a value to guard
     * against a misbehaving endpoint returning something unreasonable.
     */
    val maxMetadataBytes: Long? = null,
) {
    internal fun allowsScheme(scheme: String?): Boolean =
        scheme != null && allowedSchemes.any { it.equals(scheme, ignoreCase = true) }

    companion object {

        /** The SDK's existing reach. */
        @JvmField
        val Default = DiscoveryPolicy()

        /** OpenID4VCI 1.0 as written: https only, no fallbacks, no drafts. */
        @JvmField
        val Strict = DiscoveryPolicy(
            allowedSchemes = setOf("https"),
            allowSuffixWellKnownFallback = false,
            allowOpenIdConfigurationFallback = false,
            allowDraftMetadata = false,
            requireJsonContentType = true,
            requireIssuerIdentifierMatch = true,
            maxMetadataBytes = 512L * 1024L,
        )
    }
}
