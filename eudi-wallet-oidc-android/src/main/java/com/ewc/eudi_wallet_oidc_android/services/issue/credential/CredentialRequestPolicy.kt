package com.ewc.eudi_wallet_oidc_android.services.issue.credential

/**
 * What the SDK sends and accepts when making a credential request.
 *
 * [Default] is OpenID4VCI 1.0 as written; the flags exist to step back from it against an issuer
 * that has not caught up, not to opt into it.
 */
data class CredentialRequestPolicy(

    /**
     * Send the plural `proofs` object when the issuer declares `proof_types_supported` for the
     * credential being requested.
     *
     * Section 8.2: "The `proofs` parameter MUST be present if the `proof_types_supported` parameter
     * is present in the `credential_configurations_supported` parameter of the Issuer metadata."
     *
     * On by default, because that is the rule. Both SDKs previously keyed this off whether the
     * metadata contained a `credential_metadata` member -- an unrelated marker, read from an
     * arbitrary configuration rather than the requested one.
     */
    val usePluralProofs: Boolean = true,

    /**
     * Re-sign the proof and retry once when the issuer rejects it with a fresh nonce.
     *
     * Section 8.3.1: "The Credential Issuer MAY return a new `c_nonce` value in an error response",
     * and the wallet should retry with it. Applies to `invalid_proof` and `invalid_nonce`. Exactly
     * once -- never a loop.
     */
    val retryOnStaleNonce: Boolean = true,

    /**
     * Retry once when the credential endpoint demands a DPoP nonce (RFC 9449 section 8).
     *
     * The token endpoint already does this; the credential endpoint never has.
     */
    val retryOnDPoPNonce: Boolean = true,
) {
    companion object {
        @JvmField
        val Default = CredentialRequestPolicy()

        /** For an issuer that rejects the 1.0 shapes: singular `proof`, no retries. */
        @JvmField
        val Legacy = CredentialRequestPolicy(
            usePluralProofs = false,
            retryOnStaleNonce = false,
            retryOnDPoPNonce = false,
        )
    }
}
