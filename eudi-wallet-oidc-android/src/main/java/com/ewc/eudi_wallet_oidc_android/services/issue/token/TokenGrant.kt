package com.ewc.eudi_wallet_oidc_android.services.issue.token

/**
 * Which grant the token request uses, and the values that grant needs.
 *
 * The credential offer decides this, not the caller and not the server -- which is why this is a
 * sealed type rather than a registry like the authorization transports.
 *
 * It replaces four loose parameters (`code`, `codeVerifier`, `isPreAuthorisedCodeFlow`, `userPin`)
 * in which illegal states were representable: `isPreAuthorisedCodeFlow = false` with a `userPin`
 * set was expressible and meaningless. Section 6.1 says `tx_code` "MUST only be used if the
 * grant_type is `urn:ietf:params:oauth:grant-type:pre-authorized_code`"; here that rule cannot be
 * broken, rather than merely being unwritten.
 */
sealed class TokenGrant {

    /** The wire value of `grant_type`. */
    abstract val grantType: String

    /**
     * The code from an authorization request (OpenID4VCI section 6.1, RFC 6749 section 4.1.3).
     *
     * @param redirectUri **must be the value the authorization request actually sent** -- read it
     *   from `AuthorizationResponse.request.redirectUri` rather than re-deriving it. RFC 6749
     *   section 4.1.3 requires the two to be identical.
     */
    data class AuthorizationCode(
        val code: String,
        val codeVerifier: String?,
        val redirectUri: String? = null,
    ) : TokenGrant() {
        override val grantType = AUTHORIZATION_CODE
    }

    /**
     * The code the credential offer carried, for issuance the user never authorized in a browser.
     *
     * @param txCode the Transaction Code the user typed. Section 6.1: it "MUST be present if a
     *   `tx_code` object was present in the Credential Offer (including if the object was empty)",
     *   so whether one is *needed* is a property of the offer -- see
     *   [TokenRequestParameters.requiresTransactionCode] -- not of whether the caller happens to
     *   have one.
     */
    data class PreAuthorized(
        val code: String,
        val txCode: String? = null,
    ) : TokenGrant() {
        override val grantType = PRE_AUTHORIZED_CODE
    }

    companion object {
        const val AUTHORIZATION_CODE = "authorization_code"
        const val PRE_AUTHORIZED_CODE = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    }
}
