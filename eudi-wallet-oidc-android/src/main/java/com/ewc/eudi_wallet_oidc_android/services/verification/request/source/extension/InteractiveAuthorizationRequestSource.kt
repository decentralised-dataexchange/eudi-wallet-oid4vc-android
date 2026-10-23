package com.ewc.eudi_wallet_oidc_android.services.verification.request.source.extension

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.request.AuthorizationRequestUri
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestException
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy
import com.ewc.eudi_wallet_oidc_android.services.verification.request.RequestObjectParser
import com.ewc.eudi_wallet_oidc_android.services.verification.request.source.PresentationRequestSource
import com.google.gson.Gson

/**
 * EXTENSION, not part of OpenID4VP 1.0: the interactive authorization request of the EWC
 * issuance profile, where an issuer asks for a presentation in the middle of issuance.
 *
 * The presentation request arrives as `?openid4vp_request=<JSON>` next to `auth_session`,
 * `status` and `type`. The JSON may itself carry a `request` object, whose payload then replaces
 * the outer parameters except for `client_id`, which stays the issuer's.
 */
class InteractiveAuthorizationRequestSource : PresentationRequestSource {

    override val name: String = "openid4vp_request"

    override fun supports(data: String): Boolean = AuthorizationRequestUri.hasQueryParam(data, PARAM)

    override suspend fun retrieve(data: String, policy: PresentationRequestPolicy): PresentationRequest {
        val openid4vpRequest = AuthorizationRequestUri.queryParam(data, PARAM)
            ?.takeIf { it.isNotBlank() }
            ?: throw PresentationRequestException.Malformed()

        var request = try {
            Gson().fromJson(openid4vpRequest, PresentationRequest::class.java)
        } catch (e: Exception) {
            null
        } ?: throw PresentationRequestException.Malformed()

        val issuerClientId = request.clientId
        val requestObject = request.request
        if (requestObject != null && RequestObjectParser.looksLikeJwt(requestObject)) {
            request = try {
                RequestObjectParser.parse(requestObject)
            } catch (e: PresentationRequestException) {
                request // an unreadable inner object leaves the outer parameters in force
            }
        }

        request.authSession = AuthorizationRequestUri.queryParam(data, "auth_session")
        request.status = AuthorizationRequestUri.queryParam(data, "status")
        request.type = AuthorizationRequestUri.queryParam(data, "type")
        request.clientId = issuerClientId
        request.request = requestObject ?: openid4vpRequest
        return request
    }

    private companion object {
        const val PARAM = "openid4vp_request"
    }
}
