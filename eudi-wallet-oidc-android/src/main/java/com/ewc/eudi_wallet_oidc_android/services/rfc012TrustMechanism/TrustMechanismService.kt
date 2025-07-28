package com.ewc.eudi_wallet_oidc_android.services.rfc012TrustMechanism

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.DigitalId
import com.ewc.eudi_wallet_oidc_android.models.Root
import com.ewc.eudi_wallet_oidc_android.models.ServiceInformation
import com.ewc.eudi_wallet_oidc_android.models.TSPService
import com.ewc.eudi_wallet_oidc_android.models.TSPServices
import com.ewc.eudi_wallet_oidc_android.models.TrustServiceProvider
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletAttestationUtil.TAG
import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonParser

class TrustMechanismService : TrustMechanismInterface {
    val gson = Gson()
    override suspend fun isIssuerOrVerifierTrusted(
        url: String?,
        x5c: String?
    ): Boolean {
        return try {
            val service = ApiManager.api.getService()
            if (service == null) {
                Log.e(TAG, "API service is null")
                return false
            }

            val response =
                service.getTrustServiceProviders(url?:"https://ewc-consortium.github.io/ewc-trust-list/EWC-TL")

            if (response.isSuccessful) {
                val responseBody = response.body()
                if (responseBody != null) {
                    val xmlString = responseBody.string()
                    val jsonString = XmlFetchParserUtil.parseXmlToJsonString(xmlString)

                    val rootObj = gson.fromJson(jsonString, Root::class.java)

                    val tspList =
                        rootObj.trustServiceProviderList?.trustServiceProvider ?: emptyList()

                    val matchedTsp = findMatchedTrustServiceProvider(
                        tspList,
                        x5c,
                    )

                    val hasGranted = hasGrantedServiceStatus(matchedTsp?.tspServices, gson)

                    println("Has granted status: $hasGranted")

                    return hasGranted
                } else {
                    Log.e(TAG, "Response body is null")
                    false
                }
            } else {
                Log.e(TAG, "Failed to fetch trust details: ${response.errorBody()?.string()}")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error fetching trust details: ${e.message}", e)
            false
        }
    }


    override suspend fun fetchTrustDetails(
        url: String?,
        x5c: String?
    ): TrustServiceProvider? {
        return try {
            val service = ApiManager.api.getService()
            if (service == null) {
                Log.e(TAG, "API service is null")
                return null
            }

            val response = service.getTrustServiceProviders(
                url ?: "https://ewc-consortium.github.io/ewc-trust-list/EWC-TL"
            )

            if (response.isSuccessful) {
                val responseBody = response.body()
                if (responseBody != null) {
                    val xmlString = responseBody.string()
                    val jsonString = XmlFetchParserUtil.parseXmlToJsonString(xmlString)

                    val rootObj = gson.fromJson(jsonString, Root::class.java)

                    val tspList =
                        rootObj.trustServiceProviderList?.trustServiceProvider ?: emptyList()

                    val matchedTsp = findMatchedTrustServiceProvider(
                        tspList,
                        x5c = x5c,
                    )

                    return matchedTsp

                } else {
                    Log.e(TAG, "Response body is null")
                    null
                }
            } else {
                Log.e(TAG, "Failed to fetch trust details: ${response.errorBody()?.string()}")
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error fetching trust details: ${e.message}", e)
            null
        }
    }

    private fun hasGrantedServiceStatus(tspServices: TSPServices?, gson: Gson): Boolean {
        val rawTspService = tspServices?.tspService ?: return false
        val jsonElement = gson.toJsonTree(rawTspService)

        fun extractServiceStatus(serviceInfoAny: Any?): String? {
            if (serviceInfoAny == null) return null
            val jsonString = gson.toJson(serviceInfoAny)
            val element = JsonParser.parseString(jsonString)

            // ServiceInformation itself can be object or array
            return when {
                element.isJsonObject -> element.asJsonObject.get("ServiceStatus")?.asString
                element.isJsonArray -> {
                    // If array, get the first ServiceStatus or any matching you want
                    element.asJsonArray.firstOrNull()?.asJsonObject?.get("ServiceStatus")?.asString
                }

                else -> null
            }
        }

        return when {
            jsonElement.isJsonArray -> {
                jsonElement.asJsonArray.any { item ->
                    val service = gson.fromJson(item, TSPService::class.java)
                    extractServiceStatus(service.serviceInformation)?.contains(
                        "granted",
                        ignoreCase = true
                    ) == true
                }
            }

            jsonElement.isJsonObject -> {
                val service = gson.fromJson(jsonElement, TSPService::class.java)
                extractServiceStatus(service.serviceInformation)?.contains(
                    "granted",
                    ignoreCase = true
                ) == true
            }

            else -> false
        }
    }
    private fun findMatchedTrustServiceProvider(
        tspList: List<TrustServiceProvider>,
        x5c: String?
    ): TrustServiceProvider? {
        if (x5c.isNullOrBlank()) return null

        //var fallbackMatch: TrustServiceProvider? = null
        val separator = "##SEP##"
        var kid: String? = null
        var jwksUri: String? = null

        if (x5c.contains(separator)) {
            val parts = x5c.split(separator, limit = 2)
            kid = parts.getOrNull(0)
            jwksUri = parts.getOrNull(1)
        }


        try {
            for (tsp in tspList) {
                val rawTspService = tsp.tspServices?.tspService ?: continue
                val tspJson = gson.toJsonTree(rawTspService)

                val tspServiceElements = when {
                    tspJson.isJsonArray -> tspJson.asJsonArray
                    tspJson.isJsonObject -> JsonArray().apply { add(tspJson.asJsonObject) }
                    else -> continue
                }

                for (tspElement in tspServiceElements) {
                    val tspService = gson.fromJson(tspElement, TSPService::class.java)
                    val rawServiceInfo = tspService.serviceInformation ?: continue
                    val serviceInfoJson = gson.toJsonTree(rawServiceInfo)

                    val serviceInfoElements = when {
                        serviceInfoJson.isJsonArray -> serviceInfoJson.asJsonArray
                        serviceInfoJson.isJsonObject -> JsonArray().apply { add(serviceInfoJson.asJsonObject) }
                        else -> continue
                    }

                    for (serviceInfoElement in serviceInfoElements) {
                        val serviceInfo = gson.fromJson(serviceInfoElement, ServiceInformation::class.java)
                        val digitalIdRaw = serviceInfo.serviceDigitalIdentity?.digitalId ?: continue
                        val digitalIdJson = gson.toJsonTree(digitalIdRaw)

                        val digitalIdElements = when {
                            digitalIdJson.isJsonArray -> digitalIdJson.asJsonArray
                            digitalIdJson.isJsonObject -> JsonArray().apply { add(digitalIdJson.asJsonObject) }
                            else -> continue
                        }

                        for (digitalIdElement in digitalIdElements) {

                            val digitalId = gson.fromJson(digitalIdElement, DigitalId::class.java)
                            Log.d("TrustMechanismService", "Checking DigitalId: x509Cert=${digitalId.x509Certificate}, x509SKI=${digitalId.x509SKI}, DID=${digitalId.did}, KID=${digitalId.kid}, JwksURI=${digitalId.jwksURI}")


                            // First priority: match x509Certificate
                            if (digitalId.x509Certificate?.trim()?.equals(x5c.trim(), ignoreCase = true) == true) {
                                return tsp
                            }

                            // match x509SKI
                            if (digitalId.x509SKI?.trim()?.equals(x5c.trim(), ignoreCase = true) == true) {
                                return tsp
                            }
                            // match DID
                            if (digitalId.did?.trim()?.equals(x5c.trim(), ignoreCase = true) == true) {
                                return tsp
                            }
                            // Match kid and jwksUri only if both present
                            if (kid != null && jwksUri != null) {
                                if (digitalId.kid?.trim()?.equals(kid.trim(), ignoreCase = true) == true &&
                                    digitalId.jwksURI?.trim()?.equals(jwksUri.trim(), ignoreCase = true) == true) {
                                    return tsp
                                }
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.e("Error", "Exception in findMatchedTrustServiceProvider", e)
            return null
        }

        // Return fallback match if found, else null
        return null
    }
}
