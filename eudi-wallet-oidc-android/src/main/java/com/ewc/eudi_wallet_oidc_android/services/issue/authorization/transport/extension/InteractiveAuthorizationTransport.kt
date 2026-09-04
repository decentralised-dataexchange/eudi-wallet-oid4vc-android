package com.ewc.eudi_wallet_oidc_android.services.issue.authorization.transport.extension

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
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.transport.AuthorizationRequestTransport
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.google.gson.Gson

/**
 * IAR -- Interactive Authorization Request. **A profile extension, not a specification feature.**
 *
 * `interactive_authorization_endpoint` appears in no published specification: not OpenID4VCI, not
 * RFC 8414, not OpenID Connect Discovery. It is required by the issuers this wallet talks to and
 * must not be removed, but it also must not be mistaken for something standard.
 *
 * How it works. Instead of sending the user to the authorization endpoint, the wallet POSTs the
 * authorization parameters to the interactive endpoint together with
 * `interaction_types_supported`, declaring what it can handle. The server answers with a `type`:
 *
 *  - `openid4vp_presentation` -- it wants a presentation before authorizing. The wallet builds an
 *    authorization URL carrying `auth_session` and the embedded `openid4vp_request`, with
 *    `client_id` rewritten to `iar:<endpoint>` so the presentation side can recognise the scheme
 *    (see `ClientIdScheme.IAR` and `ResponseModes.IAR_POST`);
 *  - `redirect_to_web` -- it answers with a `request_uri` to continue at the authorization endpoint.
 *
 * Behaviour is unchanged from the previous implementation, with one exception: a failed call or an
 * unrecognised `type` used to be logged and then fall through to a bare `null`, which the caller
 * could not distinguish from anything else. Both now report a reason.
 */
internal class InteractiveAuthorizationTransport : AuthorizationRequestTransport {

    override val kind = AuthorizationTransportKind.INTERACTIVE_AUTHORIZATION

    override val name: String = "interactive_authorization"

    /** The interactive endpoint, which is where the request is POSTed -- not `authorization_endpoint`. */
    override fun endpointFor(session: IssuanceSession): String? =
        session.authConfig?.interactiveAuthorizationEndpoint

    /** What this wallet can be asked to do mid-authorization. */
    private val interactionTypesSupported = "openid4vp_presentation,redirect_to_web"

    override fun supports(
        session: IssuanceSession,
        mode: AuthorizationMode,
        policy: AuthorizationRequestPolicy,
    ): Boolean = policy.allowInteractiveAuthorization &&
        !session.authConfig?.interactiveAuthorizationEndpoint.isNullOrEmpty()

    override suspend fun perform(
        parameters: AuthorizationRequestParameters,
        session: IssuanceSession,
        wallet: WalletIdentity,
        headers: Map<String, String>,
        mode: AuthorizationMode,
    ): AuthorizationResponse {
        val interactiveEndpoint = session.authConfig?.interactiveAuthorizationEndpoint.orEmpty()
        val authorizationEndpoint = session.authConfig?.authorizationEndpoint
            ?: throw AuthorizationException.NoAuthorizationEndpoint()

        val response = AuthorizationHttp.call {
            ApiManager.api.getService()?.interactiveAuthorizationRequest(
                interactiveEndpoint,
                parameters.toMap() + mapOf("interaction_types_supported" to interactionTypesSupported),
                headers,
            )
        }
        if (!response.isSuccessful) {
            throw AuthorizationException.Rejected(response.code(), AuthorizationHttp.errorBody(response))
        }

        val body = response.body()
        return when (body?.type) {
            TYPE_PRESENTATION -> {
                // The presentation side identifies the verifier by this scheme.
                body.openid4vpRequest?.clientId = "iar:$interactiveEndpoint"
                val url = AuthorizationUri.appendQueryParameters(
                    authorizationEndpoint,
                    mapOf(
                        "client_id" to parameters.clientId,
                        "status" to body.status,
                        "type" to body.type,
                        "auth_session" to body.authSession,
                        "openid4vp_request" to body.openid4vpRequest?.let { Gson().toJson(it) },
                    ),
                )
                AuthorizationResponse.presentationRequired(
                    url = url,
                    authSession = body.authSession,
                    expiresIn = body.expiresIn,
                )
            }

            TYPE_REDIRECT_TO_WEB -> {
                AuthorizationResponse.openInBrowser(
                    AuthorizationUri.appendQueryParameters(
                        authorizationEndpoint,
                        mapOf("client_id" to parameters.clientId, "request_uri" to body.requestUri),
                    ),
                    expiresIn = body.expiresIn,
                )
            }

            else -> throw AuthorizationException.Unusable(
                "This issuer asked for an interaction this wallet does not support: ${body?.type ?: "none"}"
            )
        }
    }

    private companion object {
        const val TYPE_PRESENTATION = "openid4vp_presentation"
        const val TYPE_REDIRECT_TO_WEB = "redirect_to_web"
    }
}
