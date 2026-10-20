package com.ewc.eudi_wallet_oidc_android.services.verification.request.source

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.request.AuthorizationRequestUri
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestException
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy
import com.ewc.eudi_wallet_oidc_android.services.verification.request.RequestObjectParser

/**
 * The request object travels by value.
 *
 * Two shapes: RFC 9101 section 5.1, `?client_id=...&request=<JWT>`, and a bare JWT scanned on its
 * own with no URI around it. The bare form is not in OpenID4VP 1.0 and is kept for the verifiers
 * that still print it (EWC RFC002 section 3.1.3).
 */
class RequestObjectSource : PresentationRequestSource {

    override val name: String = "request"

    override fun supports(data: String): Boolean =
        AuthorizationRequestUri.hasQueryParam(data, PARAM) || RequestObjectParser.looksLikeJwt(data)

    override suspend fun retrieve(data: String, policy: PresentationRequestPolicy): PresentationRequest {
        val byParameter = AuthorizationRequestUri.queryParam(data, PARAM)
        if (byParameter != null) {
            if (!RequestObjectParser.looksLikeJwt(byParameter)) throw PresentationRequestException.Malformed()
            val request = RequestObjectParser.parse(byParameter)
            RequestObjectParser.requireMatchingClientId(AuthorizationRequestUri.queryParam(data, "client_id"), request)
            return request
        }
        return RequestObjectParser.parse(data)
    }

    private companion object {
        const val PARAM = "request"
    }
}
