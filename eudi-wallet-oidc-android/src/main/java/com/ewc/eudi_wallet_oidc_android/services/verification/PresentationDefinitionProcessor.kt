package com.ewc.eudi_wallet_oidc_android.services.verification

import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.google.gson.Gson
import com.google.gson.internal.LinkedTreeMap
import android.util.Log

object PresentationDefinitionProcessor {

    /**
     * Converts a raw object (PresentationDefinition, LinkedTreeMap, or JSON string)
     * into a PresentationDefinition instance.
     */
    fun processPresentationDefinition(presentationDefinition: Any?): PresentationDefinition {
        return try {
            when (presentationDefinition) {
                is PresentationDefinition -> presentationDefinition

                is LinkedTreeMap<*, *> -> {
                    val jsonString = Gson().toJson(presentationDefinition)
                    Gson().fromJson(jsonString, PresentationDefinition::class.java)
                }

                is String -> Gson().fromJson(
                    presentationDefinition,
                    PresentationDefinition::class.java
                )

                else -> {
                    Log.e("PresentationDefinitionProcessor", "Invalid presentation definition format")
                    PresentationDefinition()
                }
            }
        } catch (e: Exception) {
            Log.e("PresentationDefinitionProcessor", "Error processing presentation definition", e)
            PresentationDefinition()
        }
    }
}
