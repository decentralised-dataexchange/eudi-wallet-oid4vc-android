package com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest

import android.net.Uri
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall.safeApiCallResponse
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.isValidJWT
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.parseJWTForPayload
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest.ProcessPresentationRequestWithUris.processPresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.ClientIdScheme
import com.ewc.eudi_wallet_oidc_android.services.verification.clientIdSchemeHandling.ClientIdParser
import com.google.gson.Gson
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.PlainJWT

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

    /** True when the request object carries no signature: a plain JWT (`alg: none`). */
    private fun isUnsignedRequestObject(jwt: String): Boolean = try {
        JWTParser.parse(jwt.trim()) is PlainJWT
    } catch (e: Exception) {
        false
    }

    /** True when the client id scheme, explicit or taken from the client_id prefix, is redirect_uri. */
    private fun isRedirectUriScheme(request: PresentationRequest): Boolean {
        val scheme = request.clientIdScheme?.takeIf { it.isNotBlank() }
            ?.let { ClientIdScheme.fromScheme(it) }
            ?: ClientIdParser.getClientIdScheme(request.clientId ?: "")
        return scheme == ClientIdScheme.REDIRECT_URI
    }
    override suspend fun processAuthorisationRequest(
        authorisationRequestData: String
    ): WrappedPresentationRequest {
        val uri = Uri.parse(authorisationRequestData)
        val gson = Gson()
        val requestUri = uri.getQueryParameter("request_uri")

        return try {
            val result = safeApiCallResponse {
                ApiManager.api.getService()
                    ?.getPresentationDefinitionFromRequestUri(requestUri ?: "")
            }

            result.fold(
                onSuccess = { response ->
                    val responseString = response.body()?.string()

                    if (responseString.isNullOrBlank()) {
                        return WrappedPresentationRequest(
                            presentationRequest = null,
                            errorResponse = ErrorResponse(
                                error = null,
                                errorDescription = "Response is null or empty."
                            )
                        )
                    }

                    // Try parsing as JSON first
                    val json: PresentationRequest? = try {
                        gson.fromJson(responseString, PresentationRequest::class.java)
                    } catch (e: Exception) {
                        null // If JSON parsing fails, fall back to JWT validation
                    }

                    if (json != null) {
                        processPresentationRequest(json)
                    } else {
                        if (isValidJWT(responseString)) {
                            val payload = parseJWTForPayload(responseString)
                            val jwtJson = gson.fromJson(payload, PresentationRequest::class.java)
                            jwtJson.request = jwtJson.request ?: responseString
                            // OpenID4VP 1.0: a redirect_uri request MUST NOT be signed, so an unsigned
                            // request object (alg none) is the normal shape for that scheme and is
                            // accepted as it is. For every other scheme the signature is what
                            // identifies the verifier, so an unsigned one is refused.
                            if (isUnsignedRequestObject(responseString) && !isRedirectUriScheme(jwtJson)) {
                                return WrappedPresentationRequest(
                                    presentationRequest = null,
                                    errorResponse = ErrorResponse(
                                        error = null,
                                        errorDescription = "Request validation failed"
                                    )
                                )
                            }
                            processPresentationRequest(jwtJson)
                        } else {
                            WrappedPresentationRequest(
                                presentationRequest = null,
                                errorResponse = ErrorResponse(
                                    error = null,
                                    errorDescription = "Invalid Request"
                                )
                            )
                        }
                    }
                },
                onFailure = { error ->
                    WrappedPresentationRequest(
                        presentationRequest = null,
                        errorResponse = ErrorResponse(
                            error = null,
                            errorDescription = error.message ?: "Unable to process request"
                        )
                    )
                }
            )
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