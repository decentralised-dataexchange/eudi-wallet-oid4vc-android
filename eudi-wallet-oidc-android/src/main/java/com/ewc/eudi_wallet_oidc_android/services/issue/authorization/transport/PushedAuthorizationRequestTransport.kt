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
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager

/**
 * Pushed Authorization Requests, RFC 9126.
 *
 * OpenID4VCI 1.0 section 5: "When the grant type authorization_code is used, it is RECOMMENDED to
 * use PKCE [RFC7636] and Pushed Authorization Requests [RFC9126]." Used when the authorization
 * server sets `require_pushed_authorization_requests`.
 *
 * The parameters are POSTed to the PAR endpoint, which answers with a `request_uri`; the
 * authorization request then carries only `client_id` and that `request_uri`.
 */
internal class PushedAuthorizationRequestTransport : AuthorizationRequestTransport {

    override val kind = AuthorizationTransportKind.PUSHED

    override val name: String = "pushed_authorization_request"

    /** The PAR endpoint, not the authorization endpoint: that is where the request is POSTed. */
    override fun endpointFor(session: IssuanceSession): String? =
        session.authConfig?.pushedAuthorizationRequestEndpoint

    override fun supports(
        session: IssuanceSession,
        mode: AuthorizationMode,
        policy: AuthorizationRequestPolicy,
    ): Boolean = session.authConfig?.requirePushedAuthorizationRequests == true

    override suspend fun perform(
        parameters: AuthorizationRequestParameters,
        session: IssuanceSession,
        wallet: WalletIdentity,
        headers: Map<String, String>,
        mode: AuthorizationMode,
    ): AuthorizationResponse {
        val authorizationEndpoint = session.authConfig?.authorizationEndpoint
            ?: throw AuthorizationException.NoAuthorizationEndpoint()

        // The parameters and attestation headers are deliberately not logged: they carry the
        // wallet attestation and its proof of possession, which are credentials in their own right.
        Logger.d(TAG, "PAR POST ${session.authConfig.pushedAuthorizationRequestEndpoint}")

        val response = AuthorizationHttp.call {
            ApiManager.api.getService()?.processParAuthorisationRequest(
                session.authConfig.pushedAuthorizationRequestEndpoint.orEmpty(),
                parameters.toMap(),
                headers,
            )
        }
        if (!response.isSuccessful) {
            // A rejected PAR used to be swallowed silently. The Date header is the server's own
            // clock -- compare it with the proof-of-possession `iat` when a rejection looks like
            // clock skew.
            // Now actually reachable for a 4xx. The Date header is the server's own clock --
            // compare it with the proof-of-possession `iat` when a rejection looks like skew.
            Logger.e(TAG, "PAR rejected code=${response.code()} serverDate=${response.headers()["Date"]}")
            throw AuthorizationException.Rejected(response.code(), AuthorizationHttp.errorBody(response))
        }

        val requestUri = response.body()?.requestUri.orEmpty()
        if (requestUri.isBlank()) {
            throw AuthorizationException.Unusable(
                "The authorization server returned no request_uri",
                status = response.code(),
            )
        }

        // RFC 9126 section 2.2: how long the request_uri stays usable. Deserialised all along and
        // never read, so the caller could not tell a fresh hand-off from an expired one.
        val expiresIn = response.body()?.expiresIn

        val authorizationUrl = AuthorizationUri.appendQueryParameters(
            authorizationEndpoint,
            mapOf("client_id" to parameters.clientId, "request_uri" to requestUri),
        )

        if (mode == AuthorizationMode.Browser) {
            return AuthorizationResponse.openInBrowser(authorizationUrl, expiresIn = expiresIn)
        }

        // In-app: follow the authorization endpoint ourselves rather than handing it to a browser.
        //
        // Deliberately not shared with InAppAuthorizationRequestTransport. The follow-up to a PAR
        // reads a response in its own way -- a 302 Location is returned verbatim, an HTML body means
        // the final request URL is the answer -- and merging the two interpretations would change
        // behaviour for one of them.
        return followAfterPush(authorizationEndpoint, parameters.clientId, requestUri, expiresIn)
    }

    private suspend fun followAfterPush(
        authorizationEndpoint: String,
        clientId: String,
        requestUri: String,
        expiresIn: Int?,
    ): AuthorizationResponse {
        val response = AuthorizationHttp.call {
            ApiManager.api.getService()?.processAuthorisationRequest(
                authorizationEndpoint,
                mapOf("client_id" to clientId, "request_uri" to requestUri),
            )
        }

        val location = response.headers()["Location"]
        Logger.d(TAG, "authorize response code=${response.code()}")

        return when {
            response.code() == 302 && !location.isNullOrEmpty() ->
                AuthorizationResponse.openInBrowser(location, expiresIn = expiresIn)

            response.isSuccessful &&
                response.headers()["Content-Type"]?.contains("text/html") == true ->
                AuthorizationResponse.openInBrowser(
                    response.raw().request.url.toString(),
                    expiresIn = expiresIn,
                )

            response.code() >= 400 -> throw AuthorizationException.Rejected(
                response.code(), AuthorizationHttp.errorBody(response)
            )

            else -> throw AuthorizationException.Unusable(
                "The authorization server gave no redirect to continue with",
                status = response.code(),
            )
        }
    }

    private companion object {
        const val TAG = "AuthorizationRequest"
    }
}
