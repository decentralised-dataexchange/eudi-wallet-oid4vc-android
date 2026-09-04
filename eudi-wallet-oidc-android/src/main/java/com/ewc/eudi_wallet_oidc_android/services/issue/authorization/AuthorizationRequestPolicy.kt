package com.ewc.eudi_wallet_oidc_android.services.issue.authorization

/**
 * What the SDK sends and accepts when making an authorization request.
 *
 * [Default] preserves the SDK's existing behaviour; [Strict] is OpenID4VCI 1.0 as written.
 *
 * Note on what is *not* configurable: `authorization_details` and `scope` are always sent together.
 * Sections 5.1.1 and 5.1.2 present them as two alternative ways of identifying the requested
 * credential, but sending both is what this SDK has always done and what deployed servers expect.
 * There was a flag for it that no code ever read, which is worse than no flag at all.
 */
data class AuthorizationRequestPolicy(

    /**
     * Send `client_metadata`. Not an OpenID4VCI authorization request parameter; it is carried for
     * servers that use it to learn the wallet's supported VP formats before asking for a
     * presentation mid-issuance.
     */
    val sendClientMetadata: Boolean = true,

    /** Allow the IAR profile extension when the authorization server advertises its endpoint. */
    val allowInteractiveAuthorization: Boolean = true,

    /**
     * Send a `resource` parameter, RFC 8707, naming the Credential Issuer.
     *
     * Sections 5.1.2 and 6.1: "If the Credential Issuer metadata contains an
     * `authorization_servers` property, it is RECOMMENDED to use a `resource` parameter [RFC8707]
     * whose value is the Credential Issuer's identifier value", so an authorization server serving
     * several issuers can tell them apart. Sent only under that condition.
     *
     * On by default: it *adds* a parameter, and section 5.1.3 requires the authorization server to
     * "ignore any unrecognized parameters".
     */
    val sendResourceParameter: Boolean = true,

    /**
     * Take `scope` from the credential configuration the offer names, per section 5.1.2, instead of
     * always sending a bare `openid`.
     *
     * **Off by default**, unlike [sendResourceParameter], because it *changes* a parameter the
     * authorization server acts on rather than adding one it must ignore. `authorization_details`
     * already identifies the credential, so this buys little and risks a server that rejects
     * scopes it did not expect. Turn it on once there is a live issuer to try it against.
     */
    val useCredentialScopes: Boolean = false,
) {
    companion object {
        @JvmField
        val Default = AuthorizationRequestPolicy()

        /** OpenID4VCI 1.0 only: no profile extensions, no non-spec parameters. */
        @JvmField
        val Strict = AuthorizationRequestPolicy(
            sendClientMetadata = false,
            allowInteractiveAuthorization = false,
            useCredentialScopes = true,
        )
    }
}
