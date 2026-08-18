package com.ewc.eudi_wallet_oidc_android.services.nonceRequest

import com.ewc.eudi_wallet_oidc_android.models.NonceResponse
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall
import com.google.gson.Gson
import java.io.IOException

class NonceService : NonceServiceInterface {
    override suspend fun fetchNonce(accessToken: String?, nonceEndPoint: String?): String? {
        if (nonceEndPoint.isNullOrBlank()) return null

        // OpenID4VCI 1.0 (§ Nonce Endpoint): the nonce request is
        // UNAUTHENTICATED. Sending an Authorization header (a Bearer copy of a
        // DPoP-bound token, at that) makes strict issuers answer 401 with an
        // empty body, and the whole flow loses its c_nonce.
        val result = SafeApiCall.safeApiCallResponse {
            ApiManager.api.getService()?.fetchNonce(nonceEndPoint, null)
        }

        var nonce: String? = null

        result.onSuccess { response ->
            if (response.isSuccessful) {
                val responseBody = response.body()?.string()
                if (!responseBody.isNullOrEmpty()) {
                    val nonceResponse = Gson().fromJson(responseBody, NonceResponse::class.java)
                    nonce = nonceResponse.cNonce
                }
            } else {
                println("Error: ${response.code()} - ${response.errorBody()?.string()}")
            }
        }.onFailure { e ->
            println("Error while fetching nonce: ${e.message}")
        }

        return nonce
    }
}
