package com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest

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
    private fun walletNonceMismatch() = WrappedPresentationRequest(
        presentationRequest = null,
        errorResponse = ErrorResponse(
            error = null,
            errorDescription = "Request validation failed"
        )
    )

    override suspend fun processAuthorisationRequest(
        authorisationRequestData: String
    ): WrappedPresentationRequest {
        val gson = Gson()
        val requestUri = RequestUriMethod.requestUri(authorisationRequestData)
        // OpenID4VP 1.0 section 5.10: `request_uri_method=post` fetches the request object with a
        // form POST carrying the wallet metadata and a fresh nonce that the verifier has to echo
        // back in the request object. Anything else is the plain GET of RFC 9101.
        val walletNonce = if (RequestUriMethod.isPost(authorisationRequestData)) RequestUriMethod.newWalletNonce() else null
        val encryptionKey = if (walletNonce != null) RequestUriMethod.newEncryptionKey() else null

        return try {
            val result = safeApiCallResponse {
                val service = ApiManager.api.getService()
                if (walletNonce != null) {
                    service?.postPresentationRequestToRequestUri(
                        requestUri ?: "",
                        mapOf(
                            RequestUriMethod.WALLET_METADATA to RequestUriMethod.walletMetadata(encryptionKey),
                            RequestUriMethod.WALLET_NONCE to walletNonce
                        ),
                        RequestUriMethod.REQUEST_OBJECT_MEDIA_TYPE
                    )
                } else {
                    service?.getPresentationDefinitionFromRequestUri(requestUri ?: "")
                }
            }

            result.fold(
                onSuccess = { response ->
                    val rawBody = response.body()?.string()
                    // A verifier given our key may answer with an encrypted request object; open
                    // it here so the rest of the handling sees the signed request JWT as usual.
                    val responseString = if (rawBody != null && encryptionKey != null) {
                        RequestUriMethod.unwrapEncrypted(rawBody, encryptionKey)
                            ?: return walletNonceMismatch()
                    } else rawBody

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
                        if (!RequestUriMethod.nonceAccepted(walletNonce, json.walletNonce)) {
                            return walletNonceMismatch()
                        }
                        processPresentationRequest(json)
                    } else {
                        if (isValidJWT(responseString)) {
                            val payload = parseJWTForPayload(responseString)
                            val jwtJson = gson.fromJson(payload, PresentationRequest::class.java)
                            jwtJson.request = jwtJson.request ?: responseString
                            // Section 5.10: a request object fetched by POST MUST carry the
                            // wallet_nonce it was asked for; without it the request is dropped.
                            if (!RequestUriMethod.nonceAccepted(walletNonce, jwtJson.walletNonce)) {
                                return walletNonceMismatch()
                            }
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