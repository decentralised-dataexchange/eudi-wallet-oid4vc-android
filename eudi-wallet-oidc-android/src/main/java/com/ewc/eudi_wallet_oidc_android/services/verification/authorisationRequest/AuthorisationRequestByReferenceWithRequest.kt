package com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest

import android.net.Uri
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.isValidJWT
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.parseJWTForPayload
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest.ProcessPresentationRequestWithUris.processPresentationRequest
import com.google.gson.Gson

/**
 * Handles the processing of authorization requests by reference using the `request` parameter,
 * as described in [EWC-RFC002 Section 3.1.3: Passing the Request](https://github.com/EWC-consortium/eudi-wallet-rfcs/blob/main/ewc-rfc002-present-verifiable-credentials.md#313-passing-the-request).
 *
 * This class extracts the `request` JWT from the authorization request URI, validates and parses
 * the JWT payload into a `PresentationRequest` object, and delegates further processing.
 * If the JWT is invalid or cannot be parsed, an error response is returned.
 */
class AuthorisationRequestByReferenceWithRequest : AuthorisationRequestHandler {
    override suspend fun processAuthorisationRequest(authorisationRequestData: String): WrappedPresentationRequest {
        val uri = Uri.parse(authorisationRequestData)
        val gson = Gson()
        val request = uri.getQueryParameter("request")

        if (isValidJWT(request)) {
            try {
                val json = gson.fromJson(
                    parseJWTForPayload(request),
                    PresentationRequest::class.java
                )
                json.request = json.request ?: request
                return processPresentationRequest(json)
            } catch (e: Exception) {
                return WrappedPresentationRequest(
                    presentationRequest = null,
                    errorResponse = ErrorResponse(
                        error = null,
                        errorDescription = "Invalid Request"
                    )
                )
            }
        }else{
            return WrappedPresentationRequest(
                presentationRequest = null,
                errorResponse = ErrorResponse(
                    error = null,
                    errorDescription = "Invalid Request"
                )
            )
        }
    }
}