package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata

import com.ewc.eudi_wallet_oidc_android.models.WrappedAuthConfigResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedIssuerConfigResponse

/** Which of the two well-known URL layouts produced a document. */
enum class WellKnownForm {
    /**
     * The spec form: the well-known string inserted between the host and the path
     * (OpenID4VCI 1.0 section 12.2.2, RFC 8414 section 3).
     */
    Insertion,

    /** The non-spec form: the well-known string appended to the identifier. */
    Suffix,
}

/**
 * What actually happened during a discovery call.
 *
 * None of this reaches the wallet, which reads only the wrapped response. It exists so each
 * rewritten function can be exercised on its own and report which internal path fired -- the thing
 * that is otherwise invisible, and the reason a non-conformant issuer looks identical to a broken
 * one today.
 */
data class IssuerMetadataDiagnostics(
    /** The identifier the well-known URLs were built from. */
    val identifier: String?,
    /** Every URL tried, in order. */
    val attemptedUrls: List<String> = emptyList(),
    /** The URL that produced the document, or null when none did. */
    val resolvedUrl: String? = null,
    /** Which layout [resolvedUrl] used. */
    val form: WellKnownForm? = null,
    /** The response's declared media type. */
    val contentType: String? = null,
    /** Which parser claimed the document. */
    val specVersion: IssuerMetadataSpecVersion? = null,
) {
    /** True when the document came from the non-spec suffix fallback. */
    val usedSuffixFallback: Boolean get() = form == WellKnownForm.Suffix
}

/** @see IssuerMetadataDiagnostics */
data class AuthServerMetadataDiagnostics(
    val identifier: String?,
    val attemptedUrls: List<String> = emptyList(),
    val resolvedUrl: String? = null,
    val form: WellKnownForm? = null,
    val contentType: String? = null,
    /**
     * Which well-known document answered: `.well-known/oauth-authorization-server` is the location
     * OpenID4VCI names, `.well-known/openid-configuration` is the OpenID Connect Discovery
     * fallback.
     */
    val wellKnown: String? = null,
) {
    /** True when the RFC 8414 location failed and OpenID Connect Discovery answered instead. */
    val usedOpenIdConfigurationFallback: Boolean
        get() = wellKnown == WellKnownUrlBuilder.OPENID_CONFIGURATION
}

/** An issuer metadata lookup: what the wallet sees, plus how it got there. */
data class DiscoveredIssuerMetadata(
    val response: WrappedIssuerConfigResponse,
    val diagnostics: IssuerMetadataDiagnostics,
)

/** An authorization server metadata lookup: what the wallet sees, plus how it got there. */
data class DiscoveredAuthServerMetadata(
    val response: WrappedAuthConfigResponse,
    val diagnostics: AuthServerMetadataDiagnostics,
)
