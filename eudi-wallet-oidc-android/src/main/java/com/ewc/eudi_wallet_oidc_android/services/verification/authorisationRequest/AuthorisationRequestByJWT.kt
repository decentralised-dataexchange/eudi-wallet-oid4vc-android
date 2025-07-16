package com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest

import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.parseJWTForPayload
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest.ProcessPresentationRequestWithUris.processPresentationRequest
import com.google.gson.Gson

/**
 * Handles the processing of authorization requests provided directly as a JWT.
 *
 * This class takes an authorization request in the form of a JWT string, parses its payload
 * into a `PresentationRequest` object, and delegates further processing. If parsing fails,
 * it returns a `WrappedPresentationRequest` containing an error response.
 *
 * Usage scenario: When the authorization request is passed as a JWT in the QR CODE,
 * as described in EWC-RFC002 Section 3.1.3.
 */
class AuthorisationRequestByJWT : AuthorisationRequestHandler {
    override suspend fun processAuthorisationRequest(authorisationRequestData: String): WrappedPresentationRequest {
        val gson = Gson()
        try {
            val json = gson.fromJson(
                parseJWTForPayload(authorisationRequestData),
                PresentationRequest::class.java
            )
            json.request = json.request?:authorisationRequestData
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
    }
}