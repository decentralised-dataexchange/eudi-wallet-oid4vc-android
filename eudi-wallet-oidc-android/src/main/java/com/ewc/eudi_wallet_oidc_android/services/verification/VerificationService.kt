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
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletUnitAttestationHeaders
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall.safeApiCallResponse
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.isValidJWT
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestOutcome
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestResolver
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse.AuthorisationResponseHandler
import com.ewc.eudi_wallet_oidc_android.services.verification.match.CredentialMatches
import com.ewc.eudi_wallet_oidc_android.services.verification.match.PresentationQuery
import com.ewc.eudi_wallet_oidc_android.services.verification.match.PresentationQueryMatcher
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.nimbusds.jose.jwk.JWK
import org.json.JSONObject

class VerificationService : VerificationServiceInterface {

    private companion object {
        const val TAG = "VerificationService"
    }

    override suspend fun resolveAuthorizationRequest(
        data: String?,
        policy: PresentationRequestPolicy
    ): PresentationRequestOutcome = PresentationRequestResolver(policy).resolve(data)

    /**
     * Kept for integrators on the previous API. Blank input still answers null, because callers
     * test for that; every other outcome is wrapped as before.
     */
    @Deprecated(
        "Use resolveAuthorizationRequest, which returns a typed outcome instead of a nullable wrapper",
        ReplaceWith("resolveAuthorizationRequest(data)")
    )
    override suspend fun processAuthorisationRequest(data: String?): WrappedPresentationRequest? {
        if (data.isNullOrBlank())
            return null

        return when (val outcome = resolveAuthorizationRequest(data)) {
            is PresentationRequestOutcome.Resolved ->
                WrappedPresentationRequest(presentationRequest = outcome.request)
            is PresentationRequestOutcome.Failed ->
                WrappedPresentationRequest(presentationRequest = null, errorResponse = outcome.error)
        }
    }

    override suspend fun processAndSendAuthorisationResponse(
        did: String?,
        subJwk: JWK?,
        presentationRequest: PresentationRequest,
        credentialList: List<String>?,
        walletUnitAttestationJWT: String?,
        walletUnitProofOfPossession: String?,
        isScaFlow: Boolean
    ): WrappedVpTokenResponse {
        val responseUri = presentationRequest.responseUri ?: presentationRequest.redirectUri
        if (responseUri.isNullOrEmpty()) {
            return WrappedVpTokenResponse(
                errorResponse = ErrorResponse(
                    error = null,
                    errorDescription = "Unable to resolve host: $responseUri"
                )
            )
        }

        val headers = WalletUnitAttestationHeaders.build(
            walletUnitAttestationJWT,
            walletUnitProofOfPossession
        )

        return try {
            val params = AuthorisationResponseHandler().prepareAuthorisationResponse(
                presentationRequest = presentationRequest,
                credentialList = credentialList,
                did = did,
                jwk = subJwk,
                isScaFlow = isScaFlow
            )
            Log.d("Params value:", params.toString())

            val result = safeApiCallResponse {
                ApiManager.api.getService()?.sendVPToken(
                    presentationRequest.responseUri ?: presentationRequest.redirectUri ?: "",
                    params,
                    headers
                )
            }

            result.fold(
                onSuccess = { response ->
                    when {
                        response.code() == 200 -> {
                            val bodyString = response.body()?.string()
                            val gson = Gson()
                            try {
                                val vpTokenResponse =
                                    gson.fromJson(bodyString, VPTokenResponse::class.java)
                                WrappedVpTokenResponse(
                                    vpTokenResponse = VPTokenResponse(
                                        redirectUri = vpTokenResponse.redirectUri ?: run {
                                            val jsonObject = gson.fromJson(bodyString, JsonObject::class.java)
                                            jsonObject?.get("code")?.asString?.let { "https://www.example.com?code=$it" }
                                                ?: "https://www.example.com?code=1"
                                        }
                                    )
                                )
                            } catch (e: Exception) {
                                WrappedVpTokenResponse(
                                    vpTokenResponse = VPTokenResponse(
                                        redirectUri = "https://www.example.com?code=1"
                                    )
                                )
                            }
                        }

                        response.code() == 204 -> {
                            val urlValue = response.raw().request.url.toString()
                            if (urlValue.isNullOrEmpty()) {
                                WrappedVpTokenResponse(
                                    errorResponse = ErrorResponse(
                                        error = null,
                                        errorDescription = "The response URL is missing or empty"
                                    )
                                )
                            } else {
                                WrappedVpTokenResponse(
                                    vpTokenResponse = VPTokenResponse(location = urlValue)
                                )
                            }
                        }

                        response.code() == 302 || response.code() == 200 -> {
                            val locationHeader = response.headers()["Location"]
                            if (locationHeader?.contains("error=") == true) {
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

                        response.code() >= 400 -> {
                            val errorBody = response.errorBody()?.string()
                            val errorMessage =
                                errorBody?.takeIf { it.isNotBlank() } ?: "An unexpected error occurred"
                            WrappedVpTokenResponse(
                                errorResponse = ErrorResponse(
                                    error = response.code(),
                                    errorDescription = errorMessage
                                )
                            )
                        }

                        else -> WrappedVpTokenResponse(
                            errorResponse = ErrorResponse(
                                error = response.code(),
                                errorDescription = "An unexpected error occurred"
                            )
                        )
                    }
                },
                onFailure = { error ->
                    WrappedVpTokenResponse(
                        errorResponse = ErrorResponse(
                            error = null,
                            errorDescription = error.message ?: "Network or API error occurred"
                        )
                    )
                }
            )
        } catch (e: Exception) {
            Log.e(TAG, "processAndSendAuthorisationResponse failed: ${e.message}")
            WrappedVpTokenResponse(
                errorResponse = ErrorResponse(
                    error = null,
                    errorDescription = e.message.toString()
                )
            )
        }
    }

    override suspend fun processAndSendAuthorisationResponseV2(
        did: String?,
        subJwk: JWK?,
        presentationRequest: PresentationRequest,
        credentialList: List<List<String>>?,
        walletUnitAttestationJWT: String?,
        walletUnitProofOfPossession: String?,
        isScaFlow: Boolean,
        jwkList: List<List<JWK?>>?,
        amrInherenceFactor: String?,
        amrKnowledgeFactor: String?
    ): WrappedVpTokenResponse {
        val responseUri = presentationRequest.responseUri ?: presentationRequest.redirectUri
        if (responseUri.isNullOrEmpty()) {
            return WrappedVpTokenResponse(
                errorResponse = ErrorResponse(
                    error = null,
                    errorDescription = "Unable to resolve host: $responseUri"
                )
            )
        }

        val headers = WalletUnitAttestationHeaders.build(
            walletUnitAttestationJWT,
            walletUnitProofOfPossession
        )

        return try {
            val params = AuthorisationResponseHandler().prepareAuthorisationResponseV2(
                presentationRequest = presentationRequest,
                credentialList = credentialList,
                did = did,
                jwk = subJwk,
                isScaFlow = isScaFlow,
                jwkList = jwkList,
                amrInherenceFactor = amrInherenceFactor,
                amrKnowledgeFactor = amrKnowledgeFactor
            )
            Log.d("Params value:", params.toString())

            val result = safeApiCallResponse {
                ApiManager.api.getService()?.sendVPToken(
                    presentationRequest.responseUri ?: presentationRequest.redirectUri ?: "",
                    params,
                    headers
                )
            }

            result.fold(
                onSuccess = { response ->
                    when {
                        response.code() == 200 -> {
                            val bodyString = response.body()?.string()
                            val gson = Gson()
                            try {
                                val vpTokenResponse =
                                    gson.fromJson(bodyString, VPTokenResponse::class.java)
                                WrappedVpTokenResponse(
                                    vpTokenResponse = VPTokenResponse(
                                        redirectUri = vpTokenResponse.redirectUri ?: run {
                                            val jsonObject = gson.fromJson(bodyString, JsonObject::class.java)
                                            jsonObject?.get("code")?.asString?.let { "https://www.example.com?code=$it" }
                                                ?: "https://www.example.com?code=1"
                                        }
                                    )
                                )
                            } catch (e: Exception) {
                                WrappedVpTokenResponse(
                                    vpTokenResponse = VPTokenResponse(
                                        redirectUri = "https://www.example.com?code=1"
                                    )
                                )
                            }
                        }

                        response.code() == 204 -> {
                            val urlValue = response.raw().request.url.toString()
                            if (urlValue.isNullOrEmpty()) {
                                WrappedVpTokenResponse(
                                    errorResponse = ErrorResponse(
                                        error = null,
                                        errorDescription = "The response URL is missing or empty"
                                    )
                                )
                            } else {
                                WrappedVpTokenResponse(
                                    vpTokenResponse = VPTokenResponse(location = urlValue)
                                )
                            }
                        }

                        response.code() == 302 || response.code() == 200 -> {
                            val locationHeader = response.headers()["Location"]
                            if (locationHeader?.contains("error=") == true) {
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

                        response.code() >= 400 -> {
                            val errorBody = response.errorBody()?.string()
                            val errorMessage =
                                errorBody?.takeIf { it.isNotBlank() } ?: "An unexpected error occurred"
                            WrappedVpTokenResponse(
                                errorResponse = ErrorResponse(
                                    error = response.code(),
                                    errorDescription = errorMessage
                                )
                            )
                        }

                        else -> WrappedVpTokenResponse(
                            errorResponse = ErrorResponse(
                                error = response.code(),
                                errorDescription = "An unexpected error occurred"
                            )
                        )
                    }
                },
                onFailure = { error ->
                    WrappedVpTokenResponse(
                        errorResponse = ErrorResponse(
                            error = null,
                            errorDescription = error.message ?: "Network or API error occurred"
                        )
                    )
                }
            )
        } catch (e: Exception) {
            Log.e(TAG, "processAndSendAuthorisationResponseV2 failed: ${e.message}")
            WrappedVpTokenResponse(
                errorResponse = ErrorResponse(
                    error = null,
                    errorDescription = e.message.toString()
                )
            )
        }
    }

    /**
     * Returns all the list of credentials matching for all input descriptors
     */
    override suspend fun matchCredentials(
        request: PresentationRequest,
        credentials: List<String?>
    ): CredentialMatches = PresentationQueryMatcher().match(request, credentials)

    /** Previous API: the candidates per query entry, in query order, with nothing about satisfiability. */
    @Deprecated(
        "Use matchCredentials, which names each entry and reports whether the request can be satisfied",
        ReplaceWith("matchCredentials(request, allCredentialList)")
    )
    override suspend fun filterCredentials(
        allCredentialList: List<String?>,
        queryItem: Any?
    ): List<List<String>> {
        val query = when (queryItem) {
            is DCQL -> PresentationQuery.Dcql(queryItem)
            is PresentationDefinition -> PresentationQuery.PresentationDefinition(queryItem)
            else -> {
                Log.e(TAG, "Invalid query item type: ${queryItem?.javaClass?.name}")
                return emptyList()
            }
        }
        return PresentationQueryMatcher().match(query, allCredentialList).asLegacyLists()
    }
}