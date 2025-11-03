package com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest

import com.ewc.eudi_wallet_oidc_android.models.ClientMetaDetails
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall.safeApiCallResponse
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.isValidJWT
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.parseJWTForPayload
import com.google.gson.Gson

object ClientMetadataRepository {

    suspend fun getClientMetaDataFromUri(clientMetadataUri: String?): ClientMetaDetails? {
        if (clientMetadataUri.isNullOrBlank()) return null

        return try {
            val result = safeApiCallResponse {
                ApiManager.api.getService()?.resolveUrl(clientMetadataUri)
            }

            result.fold(
                onSuccess = { response ->
                    val contentType = response.headers()["Content-Type"]
                    val responseString = response.body()?.string()
                    val gson = Gson()

                    when {
                        contentType?.contains("application/json") == true -> {
                            gson.fromJson(responseString, ClientMetaDetails::class.java)
                        }
                        isValidJWT(responseString.orEmpty()) -> {
                            gson.fromJson(
                                parseJWTForPayload(responseString.orEmpty()),
                                ClientMetaDetails::class.java
                            )
                        }
                        else -> {
                            gson.fromJson(responseString.orEmpty(), ClientMetaDetails::class.java)
                        }
                    }
                },
                onFailure = { error ->
                    println("Error fetching client metadata: ${error.message}")
                    null
                }
            )
        } catch (e: Exception) {
            println("Unexpected error fetching client metadata: ${e.message}")
            null
        }
    }
}
