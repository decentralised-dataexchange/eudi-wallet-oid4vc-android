package com.ewc.eudi_wallet_oidc_android.services.utils

import com.ewc.eudi_wallet_oidc_android.models.CredentialDetails
import com.google.gson.GsonBuilder

class CredentialMetaDataConverter {
    fun convertToCredentialDetails(map: Map<String, Any>): CredentialDetails? {
        return try {
            val gson = GsonBuilder()
                .setLenient()
                .serializeNulls()
                .create()

            val jsonString = gson.toJson(map)
            gson.fromJson(jsonString, CredentialDetails::class.java)
        } catch (e: Exception) {
            // Print the exception message to understand what went wrong
            println("Error converting map to CredentialDetails: ${e.message}")
            null
        }
    }
}