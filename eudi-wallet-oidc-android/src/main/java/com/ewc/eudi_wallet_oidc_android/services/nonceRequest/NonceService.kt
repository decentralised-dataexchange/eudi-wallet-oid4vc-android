package com.ewc.eudi_wallet_oidc_android.services.nonceRequest

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.NonceResponse
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.HttpCall
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall
import com.google.gson.Gson

class NonceService : NonceServiceInterface {
    override suspend fun fetchNonce(accessToken: String?, nonceEndPoint: String?): String? {
        if (nonceEndPoint.isNullOrBlank()) return null

        // OpenID4VCI 1.0 (section 7, Nonce Endpoint): the nonce request is unauthenticated.
        // Sending an Authorization header (a Bearer copy of a DPoP-bound token, at that) makes
        // strict issuers answer 401 with an empty body, and the whole flow loses its c_nonce.
        val result = SafeApiCall.safeApiCallResponse {
            ApiManager.api.getService()?.fetchNonce(nonceEndPoint, null)
        }

        var nonce: String? = null

        result.onSuccess { response ->
            if (response.isSuccessful) {
                val responseBody = response.body()?.string()
                if (!responseBody.isNullOrEmpty()) {
                    // A non-JSON 200 is "no nonce", not an exception for the caller to explain.
                    nonce = runCatching { Gson().fromJson(responseBody, NonceResponse::class.java)?.cNonce }
                        .onFailure { Logger.e(TAG, "nonce endpoint returned no JSON: ${it.message}") }
                        .getOrNull()
                }
            } else {
                Logger.e(TAG, "nonce endpoint ${response.code()} body=${HttpCall.summary(HttpCall.errorBody(response)) ?: "<empty>"}")
            }
        }.onFailure { e ->
            Logger.e(TAG, "nonce request failed: ${e.message}")
        }

        return nonce
    }

    private companion object {
        const val TAG = "NonceService"
    }
}
