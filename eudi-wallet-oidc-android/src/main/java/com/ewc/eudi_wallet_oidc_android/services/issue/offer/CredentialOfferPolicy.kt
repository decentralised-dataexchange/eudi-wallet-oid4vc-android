package com.ewc.eudi_wallet_oidc_android.services.issue.offer

/**
 * What the SDK will accept when resolving a credential offer.
 *
 * Kept in one place so a rule can be tightened or relaxed without touching the resolution logic.
 * [Default] preserves the SDK's existing, permissive behaviour; [Strict] is what OpenID4VCI 1.0
 * actually requires.
 */
data class CredentialOfferPolicy(

    /**
     * Schemes accepted for the `credential_offer_uri` fetch.
     *
     * The spec requires `https`. `http` is kept by default because issuers are commonly run
     * locally during development. Note that this also closes `file:`, `ftp:` and `jar:`, which the
     * previous URL check accepted.
     */
    val allowedUriSchemes: Set<String> = setOf("https", "http"),

    /** Reject a fetched offer whose `Content-Type` is not JSON. */
    val requireJsonContentType: Boolean = false,

    /** Largest offer document accepted. */
    val maxOfferBytes: Long = 256L * 1024L,

    /**
     * Reject an offer carrying both `credential_offer` and `credential_offer_uri`.
     * The spec says they MUST NOT both be present.
     */
    val rejectAmbiguousOffers: Boolean = true,

    /** Accept pre-1.0 draft offers. Set false to require OpenID4VCI 1.0. */
    val allowDraftOffers: Boolean = true,
) {
    internal fun allowsScheme(scheme: String?): Boolean =
        scheme != null && allowedUriSchemes.any { it.equals(scheme, ignoreCase = true) }

    companion object {

        /** The SDK's existing behaviour. */
        @JvmField
        val Default = CredentialOfferPolicy()

        /** OpenID4VCI 1.0 as written: https only, JSON enforced, no drafts. */
        @JvmField
        val Strict = CredentialOfferPolicy(
            allowedUriSchemes = setOf("https"),
            requireJsonContentType = true,
            allowDraftOffers = false,
        )
    }
}
