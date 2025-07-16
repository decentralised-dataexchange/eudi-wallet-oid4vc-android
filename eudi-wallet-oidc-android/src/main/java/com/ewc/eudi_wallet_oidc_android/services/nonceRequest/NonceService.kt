package com.ewc.eudi_wallet_oidc_android.services.nonceRequest

import com.ewc.eudi_wallet_oidc_android.models.NonceResponse
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.google.gson.Gson
import java.io.IOException

class NonceService : NonceServiceInterface {
    override suspend fun fetchNonce(accessToken: String?, nonceEndPoint: String?): String? {
        if (nonceEndPoint.isNullOrBlank()) return null

        return try {
            val authorizationHeader = accessToken?.takeIf { it.isNotBlank() }?.let { "Bearer $it" }
            val response = ApiManager.api.getService()?.fetchNonce(
                nonceEndPoint,
                authorizationHeader
            )

            if (response?.isSuccessful == true) {
                val responseBody = response.body()?.string()
                if (!responseBody.isNullOrEmpty()) {
                    val nonceResponse = Gson().fromJson(responseBody, NonceResponse::class.java)
                    nonceResponse.cNonce
                } else {
                    null
                }
            } else {
                println("Error: ${response?.code()} - ${response?.errorBody()?.string()}")
                null
            }
        } catch (e: IOException) {
            println("IOException while fetching nonce: ${e.message}")
            null
        } catch (e: Exception) {
            println("Unexpected error while fetching nonce: ${e.message}")
            null
        }
    }
}
