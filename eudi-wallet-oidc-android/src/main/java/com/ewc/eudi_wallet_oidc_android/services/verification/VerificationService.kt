package com.ewc.eudi_wallet_oidc_android.services.verification

import android.net.Uri
import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.VPTokenResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.WrappedVpTokenResponse
import com.ewc.eudi_wallet_oidc_android.services.UrlUtils
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.isValidJWT
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest.AuthorisationRequestByJWT
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest.AuthorisationRequestByReferenceWithRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest.AuthorisationRequestByReferenceWithRequestUri
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest.AuthorisationRequestByValue
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse.AuthorisationResponseHandler
import com.ewc.eudi_wallet_oidc_android.services.verification.filterCredentials.DCQLCredentialFilter
import com.ewc.eudi_wallet_oidc_android.services.verification.filterCredentials.PresentationDefinitionCredentialFilter
import com.google.gson.Gson
import com.nimbusds.jose.jwk.JWK

class VerificationService : VerificationServiceInterface {


    /**
     * Authorisation requests can be presented to the wallet by verifying in two ways:
     * 1) by value
     * 2) by reference as defined in JWT-Secured Authorization Request (JAR) via use of request_uri.
     *      The custom URL scheme for authorisation requests is openid4vp://.
     *
     * @param data - will accept the full data which is scanned from the QR code or deep link
     *
     * @return PresentationRequest
     */
    override suspend fun processAuthorisationRequest(data: String?): WrappedPresentationRequest? {
        if (data.isNullOrBlank())
            return null

        val uri = Uri.parse(data)
        val presentationDefinition = uri.getQueryParameter("presentation_definition")
        val presentationDefinitionUri = uri.getQueryParameter("presentation_definition_uri")

        val requestUri = uri.getQueryParameter("request_uri")
        val request = uri.getQueryParameter("request")

        if (presentationDefinition != null || presentationDefinitionUri != null) {
            return AuthorisationRequestByValue().processAuthorisationRequest(data)
        } else if (!requestUri.isNullOrBlank()) {
            return AuthorisationRequestByReferenceWithRequestUri().processAuthorisationRequest(data)
        } else if (request != null) {
            return AuthorisationRequestByReferenceWithRequest().processAuthorisationRequest(data)
        } else if (isValidJWT(data)) {
            return AuthorisationRequestByJWT().processAuthorisationRequest(data)
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

    override suspend fun processAndSendAuthorisationResponse(
        did: String?,
        subJwk: JWK?,
        presentationRequest: PresentationRequest,
        credentialList: List<String>?,
        walletUnitAttestationJWT: String?,
        walletUnitProofOfPossession: String?,
    ): WrappedVpTokenResponse {
        val responseUri = presentationRequest.responseUri ?: presentationRequest.redirectUri
        if (responseUri.isNullOrEmpty() || !UrlUtils.isHostReachable(responseUri)) {
            return WrappedVpTokenResponse(
                errorResponse = ErrorResponse(
                    error = null,
                    errorDescription = "Unable to resolve host: $responseUri"
                )
            )
        }
        val headers = mutableMapOf<String, String>().apply {
            if (!walletUnitAttestationJWT.isNullOrEmpty()) {
                this["OAuth-Client-Attestation"] = walletUnitAttestationJWT
            }
            if (!walletUnitProofOfPossession.isNullOrEmpty()) {
                this["OAuth-Client-Attestation-PoP"] = walletUnitProofOfPossession
            }
        }
        try {
            val params =
                AuthorisationResponseHandler().prepareAuthorisationResponse(
                    presentationRequest = presentationRequest,
                    credentialList = credentialList,
                    did = did,
                    jwk = subJwk
                )
            Log.d("Params value:", params.toString())
            val response = ApiManager.api.getService()?.sendVPToken(
                presentationRequest.responseUri ?: presentationRequest.redirectUri ?: "",
                params,
                headers
            )

            val tokenResponse = when {
                response?.code() == 200 -> {
                    val redirectUri = response.body()?.string()
                    val gson = Gson()
                    try {
                        val vpTokenResponse =
                            gson.fromJson(redirectUri, VPTokenResponse::class.java)
                        return WrappedVpTokenResponse(
                            vpTokenResponse = VPTokenResponse(
                                location = vpTokenResponse.redirectUri
                                    ?: "https://www.example.com?code=1"
                            )
                        )
                    } catch (e: Exception) {
                        return WrappedVpTokenResponse(
                            vpTokenResponse = VPTokenResponse(
                                location = "https://www.example.com?code=1"
                            )
                        )
                    }
                }

                response?.code() == 204 -> {
                    try {
                        val urlValue = response.raw().request.url.toString()

                        if (urlValue.isNullOrEmpty()) {
                            return WrappedVpTokenResponse(
                                vpTokenResponse = null,
                                errorResponse = ErrorResponse(
                                    error = null,
                                    errorDescription = "The response URL is missing or empty"
                                )
                            )
                        }

                        return WrappedVpTokenResponse(
                            vpTokenResponse = VPTokenResponse(location = urlValue)
                        )
                    } catch (e: Exception) {
                        e.printStackTrace() // Log the exception for debugging
                        return WrappedVpTokenResponse(
                            vpTokenResponse = null,
                            errorResponse = ErrorResponse(
                                error = null,
                                errorDescription = "An unexpected error occurred: ${e.message}"
                            )
                        )
                    }
                }


                response?.code() == 302 || response?.code() == 200 -> {
                    val locationHeader = response.headers()["Location"]
                    if (locationHeader?.contains("error=") == true) {
                        // Parse the error from the location header
                        val errorParams = locationHeader.substringAfter("?").split("&").associate {
                            val (key, value) = it.split("=")
                            key to value
                        }

                        WrappedVpTokenResponse(
                            errorResponse = ErrorResponse(
                                error = when (errorParams["error"]) {
                                    "invalid_request" -> 400
                                    else -> null
                                },
                                errorDescription = errorParams["error_description"]
                            )
                        )
                    } else {
                        WrappedVpTokenResponse(
                            vpTokenResponse = VPTokenResponse(
                                location = locationHeader ?: "https://www.example.com?code=1"
                            )
                        )
                    }

                }

                (response?.code() ?: 0) >= 400 -> {
                    val errorBody = response?.errorBody()?.string()
                    val errorMessage =
                        errorBody?.takeIf { it.isNotBlank() } ?: "An unexpected error occurred"
                    WrappedVpTokenResponse(
                        errorResponse = ErrorResponse(
                            error = response?.code(),
                            errorDescription = errorMessage
                        )
                    )
                }


                else -> WrappedVpTokenResponse(
                    errorResponse = ErrorResponse(
                        error = response?.code(),
                        errorDescription = "An unexpected error occurred"
                    )
                )
            }
            return tokenResponse
        } catch (e: Exception) {
            return WrappedVpTokenResponse(
                vpTokenResponse = null,
                errorResponse = ErrorResponse(error = null, errorDescription = e.message.toString())
            )
        }


    }

    /**
     * Returns all the list of credentials matching for all input descriptors
     */
    override suspend fun filterCredentials(
        allCredentialList: List<String?>,
        queryItem: Any?
    ): List<List<String>> {
        when (queryItem) {
            is DCQL -> {
                return DCQLCredentialFilter().filterCredentialsUsingDCQL(
                    allCredentialList,
                    queryItem
                )
            }

            is PresentationDefinition -> {
                return PresentationDefinitionCredentialFilter().filterCredentialsUsingPresentationDefinition(
                    allCredentialList,
                    queryItem
                )
            }

            else -> {
                Log.e(
                    "VerificationService",
                    "Invalid query item type: ${queryItem?.javaClass?.name}"
                )
                return emptyList()
            }
        }
    }
}