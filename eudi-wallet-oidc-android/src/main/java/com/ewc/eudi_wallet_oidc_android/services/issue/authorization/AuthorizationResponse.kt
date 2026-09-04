package com.ewc.eudi_wallet_oidc_android.services.issue.authorization

import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse

/**
 * The result of an authorization request.
 *
 * [outcome] says which case this is; every other field is documented with the outcome that fills
 * it, and is null otherwise. Serialises to JSON as-is, so it can be logged verbatim and mirrored
 * field-for-field on iOS.
 *
 * | outcome                | fields set                  |
 * |------------------------|-----------------------------|
 * | AUTHORIZATION_CODE     | code, state                 |
 * | OPEN_IN_BROWSER        | url, expiresIn              |
 * | PRESENTATION_REQUIRED  | url, authSession, expiresIn |
 * | ID_TOKEN_REQUIRED      | url                         |
 * | FAILED                 | error                       |
 *
 * [request] is set on every outcome, including failures.
 *
 * Replaces a `String?` that meant six different things and left the caller re-parsing query
 * parameters off a URL it had just been handed, to work out which.
 */
data class AuthorizationResponse(

    /** Which case this is. Switch on this first; nothing else is meaningful without it. */
    val outcome: AuthorizationOutcome,

    /**
     * The OAuth 2.0 authorization code, to be exchanged at the token endpoint.
     *
     * Set only when [outcome] is [AuthorizationOutcome.AUTHORIZATION_CODE].
     * Example: `"SplxlOBeZQQYbYS6WxSbIA"`.
     */
    val code: String? = null,

    /**
     * The `state` the authorization server echoed back -- compare it against
     * [AuthorizationRequestInfo.state] before spending [code].
     *
     * Set only with [AuthorizationOutcome.AUTHORIZATION_CODE], and only when the SDK itself saw the
     * redirect. On the browser hand-off the callback arrives at the app instead, so the app makes
     * that comparison.
     */
    val state: String? = null,

    /**
     * The URL to act on. What to *do* with it is given by [outcome]:
     *
     * - [AuthorizationOutcome.OPEN_IN_BROWSER] -- open in a browser, not a WebView (RFC 8252), so
     *   the authorization server's session cookie lands in the browser.
     *   Example: `"https://issuer.example/authorize?client_id=...&request_uri=urn:..."`.
     * - [AuthorizationOutcome.PRESENTATION_REQUIRED] -- an OpenID4VP request the issuer wants
     *   satisfied before it will authorize (the BankID SUA case). Pass unchanged to
     *   `VerificationService.processAuthorisationRequest`.
     * - [AuthorizationOutcome.ID_TOKEN_REQUIRED] -- the request to answer, carrying
     *   `response_type=id_token` and the `redirect_uri` to post to. Pass to
     *   `IssueService.processAuthorisationRequestUsingIdToken`.
     *
     * Null for [AuthorizationOutcome.AUTHORIZATION_CODE] and [AuthorizationOutcome.FAILED].
     */
    val url: String? = null,

    /**
     * The IAR profile's opaque session handle, echoed back on the presentation response so the
     * issuer can rejoin the interrupted authorization.
     *
     * Set only on the IAR presentation path; null for a plain OpenID4VP redirect, which has no such
     * handle. Treat it as opaque -- do not parse it.
     */
    val authSession: String? = null,

    /**
     * How long the hand-off stays valid, **in seconds** -- the PAR `request_uri` lifetime
     * (RFC 9126 section 2.2) or the IAR session lifetime. Null when the server did not say.
     *
     * Example: `90`. A duration, never an absolute timestamp.
     */
    val expiresIn: Int? = null,

    /**
     * Why it failed. Set only when [outcome] is [AuthorizationOutcome.FAILED], and never null when
     * it is.
     *
     * The same [ErrorResponse] the token and credential steps return, so one error shape covers the
     * whole SDK: `errorCode` is the OAuth code to branch on (`invalid_request`, `invalid_grant`,
     * `use_dpop_nonce`), `errorDescription` the text to show a user, `httpStatus` and `raw` for
     * logs.
     */
    val error: ErrorResponse? = null,

    /** What was sent, and what the caller must carry forward. Set on every outcome. */
    val request: AuthorizationRequestInfo? = null,

    /**
     * The raw redirect the outcome was read from, when there was one.
     *
     * Only the deprecated `IssueService.processAuthorisationRequest` needs this: it returns a URL,
     * and callers that have not migrated still parse `code` and `error` back out of it. New code
     * reads [code], [state] and [error] instead and can ignore this entirely.
     */
    val location: String? = null,
) {
    companion object {

        /** The authorization server returned a code; the flow can go on to the token request. */
        fun authorizationCode(code: String, state: String? = null, location: String? = null) =
            AuthorizationResponse(
                outcome = AuthorizationOutcome.AUTHORIZATION_CODE,
                code = code,
                state = state,
                location = location,
            )

        /** The user has to complete authorization in a browser. */
        fun openInBrowser(url: String, expiresIn: Int? = null) = AuthorizationResponse(
            outcome = AuthorizationOutcome.OPEN_IN_BROWSER,
            url = url,
            expiresIn = expiresIn,
            location = url,
        )

        /** The authorization server wants a presentation before it will authorize. */
        fun presentationRequired(
            url: String,
            authSession: String? = null,
            expiresIn: Int? = null,
        ) = AuthorizationResponse(
            outcome = AuthorizationOutcome.PRESENTATION_REQUIRED,
            url = url,
            authSession = authSession,
            expiresIn = expiresIn,
            location = url,
        )

        /** The authorization server asked for an ID token instead. */
        fun idTokenRequired(url: String) = AuthorizationResponse(
            outcome = AuthorizationOutcome.ID_TOKEN_REQUIRED,
            url = url,
            location = url,
        )

        /**
         * The request failed.
         *
         * Every path that used to `return null` or fall out of the bottom of the old 302-line
         * function lands here with a reason.
         */
        fun failed(error: ErrorResponse, location: String? = null) = AuthorizationResponse(
            outcome = AuthorizationOutcome.FAILED,
            error = error,
            location = location,
        )

        /** As [failed], for the paths that have only a message. */
        fun failed(
            reason: String,
            errorCode: String? = null,
            httpStatus: Int? = null,
            location: String? = null,
        ) = failed(
            ErrorResponse(
                error = -1,
                errorDescription = reason,
                errorCode = errorCode,
                httpStatus = httpStatus,
            ),
            location = location,
        )
    }
}

/** The five things an authorization request can produce. Exhaustive. */
enum class AuthorizationOutcome {
    AUTHORIZATION_CODE,
    OPEN_IN_BROWSER,
    PRESENTATION_REQUIRED,
    ID_TOKEN_REQUIRED,
    FAILED,
}

/**
 * What the authorization request actually sent.
 *
 * Not only diagnostics: [redirectUri] and [state] are needed to finish the flow correctly, and the
 * rest is what makes a server's rejection explicable. A server answering
 * `{"detail":"issuer state is not found"}` is objecting to a parameter, and the outcome alone does
 * not say which.
 */
data class AuthorizationRequestInfo(

    /**
     * Which transport ran. Three of the four can produce
     * [AuthorizationOutcome.OPEN_IN_BROWSER]; this says which did.
     */
    val transport: AuthorizationTransportKind,

    /**
     * The URL the request was actually sent to -- the PAR endpoint, the IAR endpoint, or the
     * authorization endpoint -- rather than whichever one the metadata happened to declare.
     * Example: `"https://issuer.example/par"`.
     */
    val endpoint: String? = null,

    /**
     * The `redirect_uri` that was sent. **The token request must repeat this value verbatim**
     * (RFC 6749 section 4.1.3); a different one is rejected. Do not re-derive it.
     * Example: `"datawallet://callback"`.
     */
    val redirectUri: String,

    /**
     * The `state` that was sent. **Compare the callback's `state` against this** before spending
     * the code; a mismatch means the callback is not the answer to this request.
     * Example: `"9a1c4f2e-..."`.
     */
    val state: String,

    /** The `nonce` that was sent. Example: `"44f0b8d1-..."`. */
    val nonce: String,

    /**
     * Whether `OAuth-Client-Attestation` headers were attached -- not whether the server accepted
     * them. `false` means none were available to send.
     */
    val sentWalletAttestation: Boolean = false,

    /**
     * Every parameter as it went on the wire, blanks already omitted. For logs and bug reports.
     * Keys are the wire names: `response_type`, `scope`, `state`, `client_id`,
     * `authorization_details`, `redirect_uri`, `nonce`, `code_challenge`, `code_challenge_method`,
     * `client_metadata`, `issuer_state`, `resource`.
     */
    val parameters: Map<String, String> = emptyMap(),
)

/** The four ways this SDK can make an authorization request, in the order they are tried. */
enum class AuthorizationTransportKind {

    /**
     * The IAR profile extension.
     *
     * `interactive_authorization_endpoint` appears in no released specification -- not OpenID4VCI,
     * not RFC 8414, not OpenID Connect Discovery. It is a profile extension, and it is required.
     */
    INTERACTIVE_AUTHORIZATION,

    /** RFC 9126 Pushed Authorization Request. */
    PUSHED,

    /** The wallet makes the request itself and follows the redirects. First-party flows only. */
    IN_APP,

    /** A URL for the system browser. The default for a scanned offer. */
    BROWSER,
}
