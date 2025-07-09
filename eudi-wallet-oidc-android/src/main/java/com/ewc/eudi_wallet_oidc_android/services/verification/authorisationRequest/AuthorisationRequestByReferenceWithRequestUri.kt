package com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest

import android.net.Uri
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.isValidJWT
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.parseJWTForPayload
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest.ProcessPresentationRequestWithUris.processPresentationRequest
import com.google.gson.Gson

/**
 * Handles the processing of authorization requests by reference using the `request_uri` parameter,
 * as described in [EWC-RFC002 Section 3.1.3: Passing the Request](https://github.com/EWC-consortium/eudi-wallet-rfcs/blob/main/ewc-rfc002-present-verifiable-credentials.md#313-passing-the-request).
 *
 * This class extracts the `request_uri` from the authorization request, fetches the referenced
 * presentation request from the remote endpoint, and processes it. The response can be either a
 * JSON-encoded `PresentationRequest` or a JWT. The class validates and parses the response
 * accordingly, returning a `WrappedPresentationRequest` or an error if the process fails.
 */
class AuthorisationRequestByReferenceWithRequestUri : AuthorisationRequestHandler {
    override suspend fun processAuthorisationRequest(authorisationRequestData: String): WrappedPresentationRequest {
        val uri = Uri.parse(authorisationRequestData)
        val gson = Gson()
        val requestUri = uri.getQueryParameter("request_uri")
        try {
            val response =
                ApiManager.api.getService()
                    ?.getPresentationDefinitionFromRequestUri(requestUri ?: "")

            if (response?.isSuccessful == true) {
                val responseString = response.body()?.string()

                // Check if responseString is null or empty
                if (responseString.isNullOrBlank()) {
                    return WrappedPresentationRequest(
                        presentationRequest = null,
                        errorResponse = ErrorResponse(
                            error = null,
                            errorDescription = "Response is null or empty."
                        )
                    )
                }

                // Try to parse the response as JSON
                val json: PresentationRequest? = try {
                    gson.fromJson(responseString, PresentationRequest::class.java)
                } catch (e: Exception) {
                    null // If JSON parsing fails, return null and proceed with JWT validation
                }

                if (json != null) {
                    return processPresentationRequest(json)
                } else {
                    if (isValidJWT(responseString ?: "")) {
                        val payload = parseJWTForPayload(responseString ?: "{}")
                        val jwtJson = gson.fromJson(payload, PresentationRequest::class.java)
                        jwtJson.request = jwtJson.request ?: responseString
                        return processPresentationRequest(jwtJson)

                    } else {
                        return WrappedPresentationRequest(
                            presentationRequest = null,
                            errorResponse = ErrorResponse(
                                error = null,
                                errorDescription = "Invalid Request"
                            )
                        )
                    }
                }
            } else {
                return WrappedPresentationRequest(
                    presentationRequest = null,
                    errorResponse = ErrorResponse(
                        error = null,
                        errorDescription = "Unable to process request"
                    )
                )
            }
        } catch (e: Exception) {
            return WrappedPresentationRequest(
                presentationRequest = null,
                errorResponse = ErrorResponse(
                    error = null,
                    errorDescription = e.message.toString()
                )
            )
        }
    }
}