package com.ewc.eudi_wallet_oidc_android.services.rfc012TrustMechanism

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.DigitalId
import com.ewc.eudi_wallet_oidc_android.models.Root
import com.ewc.eudi_wallet_oidc_android.models.ServiceInformation
import com.ewc.eudi_wallet_oidc_android.models.TSPService
import com.ewc.eudi_wallet_oidc_android.models.TSPServices
import com.ewc.eudi_wallet_oidc_android.models.TrustServiceProvider
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall.safeApiCallResponse
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletAttestationUtil.TAG
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonParser

class TrustMechanismService : TrustMechanismInterface {
    val gson = GsonBuilder()
        .registerTypeAdapter(TrustServiceProvider::class.java, TrustServiceProviderDeserializer())
        .create()
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

            val result = safeApiCallResponse {
                service.getTrustServiceProviders(
                    url ?: "https://ewc-consortium.github.io/ewc-trust-list/EWC-TL"
                )
            }

            result.fold(
                onSuccess = { response ->
                    val responseBody = response.body()
                    if (responseBody != null) {
                        val xmlString = responseBody.string()
                        val jsonString = XmlFetchParserUtil.parseXmlToJsonString(xmlString)

                        val rootObj = gson.fromJson(jsonString, Root::class.java)
                        val tspList =
                            rootObj.trustServiceProviderList?.trustServiceProvider ?: emptyList()

                        val matchedTsp = findMatchedTrustServiceProvider(tspList, x5c)
                        val hasGranted = hasGrantedServiceStatus(matchedTsp?.tspServices, gson)

                        println("Has granted status: $hasGranted")
                        hasGranted
                    } else {
                        Log.e(TAG, "Response body is null")
                        false
                    }
                },
                onFailure = { error ->
                    Log.e(TAG, "Failed to fetch trust details: ${error.message}")
                    false
                }
            )
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

            val result = safeApiCallResponse {
                service.getTrustServiceProviders(
                    url ?: "https://ewc-consortium.github.io/ewc-trust-list/EWC-TL"
                )
            }

            result.fold(
                onSuccess = { response ->
                    val responseBody = response.body()
                    if (responseBody != null) {
                        val xmlString = responseBody.string()
                        val jsonString = XmlFetchParserUtil.parseXmlToJsonString(xmlString)

                        val rootObj = gson.fromJson(jsonString, Root::class.java)
                        val tspList =
                            rootObj.trustServiceProviderList?.trustServiceProvider ?: emptyList()

                        findMatchedTrustServiceProvider(tspList, x5c = x5c)
                    } else {
                        Log.e(TAG, "Response body is null")
                        null
                    }
                },
                onFailure = { error ->
                    Log.e(TAG, "Failed to fetch trust details: ${error.message}")
                    null
                }
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error fetching trust details: ${e.message}", e)
            null
        }
    }

    private fun hasGrantedServiceStatus(tspServicesList: List<TSPServices>?, gson: Gson): Boolean {
        if (tspServicesList.isNullOrEmpty()) return false

        return tspServicesList.any { tspServices ->
            val rawTspService = tspServices.tspService ?: return@any false
            val element = gson.toJsonTree(rawTspService)

            when {
                element.isJsonArray -> element.asJsonArray.any { item ->
                    val service = gson.fromJson(item, TSPService::class.java)
                    serviceHasGranted(service, gson)
                }
                element.isJsonObject -> {
                    val service = gson.fromJson(element, TSPService::class.java)
                    serviceHasGranted(service, gson)
                }
                else -> false
            }
        }
    }

    private fun serviceHasGranted(service: TSPService, gson: Gson): Boolean {
        val serviceInfo = service.serviceInformation ?: return false
        val element = gson.toJsonTree(serviceInfo)

        return when {
            element.isJsonObject -> element.asJsonObject.get("ServiceStatus")?.asString
                ?.contains("granted", ignoreCase = true) == true
            element.isJsonArray -> element.asJsonArray.any {
                it.asJsonObject.get("ServiceStatus")?.asString?.contains("granted", ignoreCase = true) == true
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
        var kid: String? = x5c
        var jwksUri: String? = null

        if (x5c.contains(separator)) {
            val parts = x5c.split(separator, limit = 2)
            kid = parts.getOrNull(0)
            jwksUri = parts.getOrNull(1)
        }


        try {
            for (tsp in tspList) {
                val tspServicesList = tsp.tspServices ?: continue

                for (tspServices in tspServicesList) {
                    val rawTspService = tspServices.tspService ?: continue
                    val tspServiceElements = when (val tree = gson.toJsonTree(rawTspService)) {
                        is com.google.gson.JsonArray -> tree
                        is com.google.gson.JsonObject -> JsonArray().apply { add(tree) }
                        else -> continue
                    }

                    for (tspServiceElem in tspServiceElements) {
                        val tspService = gson.fromJson(tspServiceElem, TSPService::class.java)

                        val serviceInfoList = when (val si = tspService.serviceInformation) {
                            is List<*> -> si
                            else -> listOf(si)
                        }

                        for (serviceInfoAny in serviceInfoList) {
                            val serviceInfo = gson.fromJson(
                                gson.toJsonTree(serviceInfoAny),
                                ServiceInformation::class.java
                            )

                            val digitalIdList = when (val di = serviceInfo.serviceDigitalIdentity?.digitalId) {
                                is List<*> -> di
                                else -> listOf(di)
                            }

                            for (digitalIdAny in digitalIdList) {
                                val digitalId = digitalIdAny?.let { gson.fromJson(gson.toJsonTree(it), DigitalId::class.java) } ?: continue

                                Log.d("TrustMechanismService", "Checking DigitalId: x509Cert=${digitalId.x509Certificate}, x509SKI=${digitalId.x509SKI}, DID=${digitalId.did}, KID=${digitalId.kid}, JwksURI=${digitalId.jwksURI}")

                                // Match x509Certificate
                                if (digitalId.x509Certificate?.trim()?.equals(x5c.trim(), ignoreCase = true) == true) {
                                    return tsp
                                }
                                // Match x509SKI
                                if (digitalId.x509SKI?.trim()?.equals(x5c.trim(), ignoreCase = true) == true) {
                                    return tsp
                                }
                                // Match DID
                                if (digitalId.did?.trim()?.equals(x5c.trim(), ignoreCase = true) == true) {
                                    return tsp
                                }
                                // Match KID + JWKS URI
                                if (kid != null && jwksUri != null &&
                                    digitalId.kid?.trim()?.equals(kid.trim(), ignoreCase = true) == true &&
                                    digitalId.jwksURI?.trim()?.equals(jwksUri.trim(), ignoreCase = true) == true
                                ) {
                                    return tsp
                                }
                                // Match kid
                                if (kid != null) {
                                    if (digitalId.kid?.trim()?.equals(kid.trim(), ignoreCase = true) == true) {
                                        return tsp
                                    }
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
