package com.ewc.eudi_wallet_oidc_android.services.issue.authorization.transport

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationException
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationMode
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationRequestParameters
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationRequestPolicy
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationTransportKind
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationHttp
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationUri
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.idtoken.IdTokenResponder
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager

/**
 * The wallet makes the authorization request itself and reads the redirect, rather than handing a
 * URL to a browser.
 *
 * Used only for first-party, non-interactive flows -- the wallet-provider attestation bootstrap.
 * RFC 8252 is why it is not the default: a scanned offer must go through the browser so the
 * authorization server's session cookie lands there.
 *
 * The interpretation of the redirect is preserved exactly, including the order the cases are tested
 * in, because several deployed servers are distinguished only by which of them matches.
 */
internal class InAppAuthorizationRequestTransport(
    private val idTokenResponder: IdTokenResponder = IdTokenResponder(),
) : AuthorizationRequestTransport {

    override val kind = AuthorizationTransportKind.IN_APP

    override val name: String = "in_app"

    override fun endpointFor(session: IssuanceSession): String? =
        session.authConfig?.authorizationEndpoint

    override fun supports(
        session: IssuanceSession,
        mode: AuthorizationMode,
        policy: AuthorizationRequestPolicy,
    ): Boolean = mode == AuthorizationMode.InApp

    override suspend fun perform(
        parameters: AuthorizationRequestParameters,
        session: IssuanceSession,
        wallet: WalletIdentity,
        headers: Map<String, String>,
        mode: AuthorizationMode,
    ): AuthorizationResponse {
        val endpoint = session.authConfig?.authorizationEndpoint
            ?: throw AuthorizationException.NoAuthorizationEndpoint()

        val response = AuthorizationHttp.call {
            ApiManager.api.getService()?.processAuthorisationRequest(endpoint, parameters.toMap())
        }

        // A 502 used to throw a bare `Exception`, which is not an AuthorizationException and so
        // escaped the resolver's catch entirely -- reaching the app as a thrown exception rather
        // than a FAILED response, the one outcome this rework exists to remove. Same message.
        if (response.code() == 502) {
            throw AuthorizationException.Unusable("Unexpected error. Please try again.", status = 502)
        }

        // Preserved: the redirect is read only from a 302, and its absence is an outcome rather
        // than a crash -- it used to be a bare `return null`.
        val location = if (response.code() == 302) response.headers()["Location"] else null
        if (location.isNullOrEmpty()) {
            throw AuthorizationException.Unusable(
                "The authorization server gave no redirect to continue with",
                status = response.code(),
            )
        }

        return interpret(location, parameters, wallet, endpoint, answerIdToken = true)
    }

    /**
     * Reads a redirect the authorization server sent.
     *
     * @param answerIdToken false when this redirect is itself the answer to an ID token we just
     *   posted, so a server that asks twice cannot put us in a loop.
     */
    private suspend fun interpret(
        location: String,
        parameters: AuthorizationRequestParameters,
        wallet: WalletIdentity,
        endpoint: String,
        answerIdToken: Boolean,
    ): AuthorizationResponse {
        fun param(name: String) = AuthorizationUri.queryParameter(location, name)

        param("error")?.let { error ->
            val description = param("error_description")
            return AuthorizationResponse.failed(
                reason = description ?: error,
                errorCode = error,
                location = location,
            )
        }

        param("code")?.let { code ->
            return AuthorizationResponse.authorizationCode(
                code = code,
                state = param("state"),
                location = location,
            )
        }

        val wantsPresentation = param("presentation_definition") != null ||
            param("presentation_definition_uri") != null ||
            (
                param("request_uri") != null &&
                    param("response_type") == null &&
                    param("state") == null
                )
        if (wantsPresentation) return AuthorizationResponse.presentationRequired(location)

        val asksForIdToken = param("response_type") == "id_token" &&
            param("redirect_uri") != null

        // A redirect away from our own redirect_uri is somewhere the user has to go -- but only
        // when the server has not explicitly asked for an ID token. This order is the previous
        // implementation's, and deployed servers are distinguished by it.
        if (!asksForIdToken && !location.startsWith(parameters.redirectUri)) {
            return AuthorizationResponse.openInBrowser(location)
        }

        if (!answerIdToken) return AuthorizationResponse.idTokenRequired(location)

        // `location` is deliberately not carried here: the previous implementation returned a bare
        // null when the ID token response produced no redirect, and callers still reading the
        // deprecated String? entry point rely on that.
        val next = idTokenResponder.respond(wallet, endpoint, location)
            ?: return AuthorizationResponse.failed(
                reason = "The authorization server did not accept the wallet's identity token",
            )
        Logger.d(TAG, "answered an id_token request, continuing")
        return interpret(next, parameters, wallet, endpoint, answerIdToken = false)
    }

    private companion object {
        const val TAG = "AuthorizationRequest"
    }
}
