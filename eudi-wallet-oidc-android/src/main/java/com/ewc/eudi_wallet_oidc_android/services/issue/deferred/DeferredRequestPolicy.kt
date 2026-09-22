package com.ewc.eudi_wallet_oidc_android.services.issue.deferred

/**
 * What the SDK sends and accepts when asking for a deferred credential.
 *
 * [Default] is OpenID4VCI 1.0 as written; the flags exist to step back from it against an issuer
 * that has not caught up, not to opt into it.
 */
data class DeferredRequestPolicy(

    /**
     * Send `credential_identifier` alongside `transaction_id` when the caller has one.
     *
     * Section 9.1 permits it. On by default, because an issuer that deferred several credentials in
     * one flow has no other way to tell which is being asked about -- but it is a parameter an older
     * issuer may reject, so it can be turned off.
     */
    val sendCredentialIdentifier: Boolean = true,

    /**
     * Retry once when the deferred endpoint demands a DPoP nonce (RFC 9449 section 8).
     *
     * The same challenge the token and credential endpoints answer.
     */
    val retryOnDPoPNonce: Boolean = true,
) {
    companion object {
        @JvmField
        val Default = DeferredRequestPolicy()

        /** For an issuer still on the drafts: the bare handle, no retries. */
        @JvmField
        val Legacy = DeferredRequestPolicy(
            sendCredentialIdentifier = false,
            retryOnDPoPNonce = false,
        )
    }
}
