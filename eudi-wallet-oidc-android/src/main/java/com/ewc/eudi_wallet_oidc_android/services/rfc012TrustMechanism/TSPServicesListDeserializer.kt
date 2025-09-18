package com.ewc.eudi_wallet_oidc_android.services.rfc012TrustMechanism

import com.ewc.eudi_wallet_oidc_android.models.TSPInformation
import com.ewc.eudi_wallet_oidc_android.models.TSPServices
import com.ewc.eudi_wallet_oidc_android.models.TrustServiceProvider
import com.google.gson.JsonDeserializationContext
import com.google.gson.JsonDeserializer
import com.google.gson.JsonElement
import java.lang.reflect.Type

class TrustServiceProviderDeserializer : JsonDeserializer<TrustServiceProvider> {
    override fun deserialize(
        json: JsonElement,
        typeOfT: Type,
        context: JsonDeserializationContext
    ): TrustServiceProvider {
        val jsonObj = json.asJsonObject

        // Deserialize TSPInformation normally
        val tspInformation = context.deserialize<TSPInformation>(
            jsonObj.get("TSPInformation"),
            TSPInformation::class.java
        )

        // Normalize TSPServices
        val tspServicesElement = jsonObj.get("TSPServices")
        val tspServicesList = mutableListOf<TSPServices>()

        if (tspServicesElement != null) {
            if (tspServicesElement.isJsonArray) {
                tspServicesElement.asJsonArray.forEach { elem ->
                    tspServicesList.add(context.deserialize(elem, TSPServices::class.java))
                }
            } else if (tspServicesElement.isJsonObject) {
                tspServicesList.add(context.deserialize(tspServicesElement, TSPServices::class.java))
            }
        }

        return TrustServiceProvider(
            tspInformation = tspInformation,
            tspServices = tspServicesList
        )
    }
}





