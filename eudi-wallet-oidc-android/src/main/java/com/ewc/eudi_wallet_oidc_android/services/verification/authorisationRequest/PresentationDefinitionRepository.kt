package com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest

import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.isValidJWT
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.parseJWTForPayload
import com.google.gson.Gson

object PresentationDefinitionRepository {

    suspend fun getPresentationDefinitionFromUri(uri: String?): PresentationDefinition? {
        if (uri.isNullOrBlank()) return null

        return try {
            val response = ApiManager.api.getService()?.resolveUrl(uri)
            if (response?.isSuccessful == true) {
                val contentType = response.headers()["Content-Type"]
                val responseString = response.body()?.string()
                val gson = Gson()

                when {
                    contentType?.contains("application/json") == true -> {
                        gson.fromJson(responseString, PresentationDefinition::class.java)
                    }
                    isValidJWT(responseString.orEmpty()) -> {
                        gson.fromJson(
                            parseJWTForPayload(responseString.orEmpty()),
                            PresentationDefinition::class.java
                        )
                    }
                    else -> {
                        gson.fromJson(responseString.orEmpty(), PresentationDefinition::class.java)
                    }
                }
            } else null
        } catch (e: Exception) {
            null
        }
    }
}
