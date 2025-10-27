package com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest

import android.net.Uri
import com.ewc.eudi_wallet_oidc_android.models.ClientMetaDetails
import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.isValidJWT
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.parseJWTForPayload
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest.ProcessPresentationRequestWithUris.processPresentationRequest
import com.google.gson.Gson

/**
 * Handles the processing of authorization requests by value, as described in
 * [EWC-RFC002 Section 3.1.3: Passing the Request](https://github.com/EWC-consortium/eudi-wallet-rfcs/blob/main/ewc-rfc002-present-verifiable-credentials.md#313-passing-the-request).
 *
 * This class parses the authorization request parameters from a URI, constructs a
 * `PresentationRequest` object, and delegates further processing. It supports all
 * parameters defined in the RFC, including `client_id`, `state`, `redirect_uri`,
 * `nonce`, `presentation_definition`, `presentation_definition_uri`, and others.
 */
class AuthorisationRequestForIAR : AuthorisationRequestHandler {

    override suspend fun processAuthorisationRequest(
        authorisationRequestData: String
    ): WrappedPresentationRequest {
        val uri = Uri.parse(authorisationRequestData)
        val gson = Gson()
        val openid4vpRequest = uri.getQueryParameter("openid4vp_request")
        var request: String? = null

        var presentationRequest = gson.fromJson(openid4vpRequest, PresentationRequest::class.java)
        val iarClientId = presentationRequest.clientId
        if (presentationRequest.request != null) {
            request = presentationRequest.request
            if (isValidJWT(presentationRequest.request)) {
                try {
                    presentationRequest = gson.fromJson(
                        parseJWTForPayload(presentationRequest.request),
                        PresentationRequest::class.java
                    )
                } catch (e: Exception) {

                }
            }
        }

        val authSession = uri.getQueryParameter("auth_session")
        val status = uri.getQueryParameter("status")
        val type =  uri.getQueryParameter("type")
        val client = uri
        presentationRequest.authSession = authSession
        presentationRequest.status = status
        presentationRequest.type = type
        presentationRequest.clientId = iarClientId
        presentationRequest.request = request ?: openid4vpRequest
        return processPresentationRequest(presentationRequest)
    }
}