package com.ewc.eudi_wallet_oidc_android.services.nonceRequest

import com.ewc.eudi_wallet_oidc_android.models.NonceResponse
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall
import com.google.gson.Gson
import java.io.IOException

class NonceService : NonceServiceInterface {
    override suspend fun fetchNonce(accessToken: String?, nonceEndPoint: String?): String? {
        if (nonceEndPoint.isNullOrBlank()) return null

        val authorizationHeader = accessToken?.takeIf { it.isNotBlank() }?.let { "Bearer $it" }

        val result = SafeApiCall.safeApiCallResponse {
            ApiManager.api.getService()?.fetchNonce(nonceEndPoint, authorizationHeader)
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
