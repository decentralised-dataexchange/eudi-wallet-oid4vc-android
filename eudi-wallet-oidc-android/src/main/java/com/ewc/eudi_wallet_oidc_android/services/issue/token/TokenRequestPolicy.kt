package com.ewc.eudi_wallet_oidc_android.services.issue.token

/**
 * What the SDK sends and accepts when making a token request.
 *
 * [Default] preserves the SDK's existing behaviour; [Strict] is OpenID4VCI 1.0 as written.
 *
 * Mirrors `AuthorizationRequestPolicy`, and like it, the shape of the request is otherwise fixed:
 * the grant decides the body.
 */
data class TokenRequestPolicy(

    /**
     * Send `resource`, RFC 8707, naming the Credential Issuer.
     *
     * Section 6.1: "If the Token Request contains a scope value related to Credential issuance and
     * the Credential Issuer's metadata contains an `authorization_servers` parameter, it is
     * RECOMMENDED to use a `resource` parameter ... whose value is the Credential Issuer's
     * identifier value."
     *
     * **Off by default**, unlike the authorization request's equivalent. There, section 5.1.3
     * requires the server to ignore parameters it does not recognise; the token endpoint has no
     * such rule, and RFC 8707 section 2 lets an authorization server reject an unknown target with
     * `invalid_target`. Turn it on once it has been tried against the issuer in question.
     */
    val sendResourceParameter: Boolean = false,

    /**
     * Send `authorization_details`, and with it `locations`.
     *
     * Section 6.1.1 permits this and section 6.2 makes the response's `authorization_details`
     * REQUIRED when it is used -- which is how `credential_identifiers` is obtained. The SDK has
     * never sent it here, and issuers currently answer with `credential_identifiers` anyway
     * because the *authorization* request carried it.
     *
     * **Off by default** for the same reason as [sendResourceParameter]: it changes a request that
     * works today.
     */
    val sendAuthorizationDetails: Boolean = false,

    /**
     * Retry once when the authorization server demands a DPoP nonce.
     *
     * RFC 9449 section 8: the server answers `400` with `{"error":"use_dpop_nonce"}` and a
     * `DPoP-Nonce` header; "the client will typically retry the request with the new nonce value
     * supplied". Exactly once -- never a loop.
     */
    val retryOnDPoPNonce: Boolean = true,
) {
    companion object {
        @JvmField
        val Default = TokenRequestPolicy()

        /** OpenID4VCI 1.0 as written: everything the specification recommends, sent. */
        @JvmField
        val Strict = TokenRequestPolicy(
            sendResourceParameter = true,
            sendAuthorizationDetails = true,
        )
    }
}
