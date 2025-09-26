package com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction

import com.ewc.eudi_wallet_oidc_android.models.DataResponse
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.nimbusds.jose.jwk.JWK
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URL
import java.net.URLDecoder

class ProcessTDWFromKID {
    suspend fun processTrustDIDWebFromKID(kid: String): JWK?{
        return try {
            if (kid.startsWith("did:tdw:")){
                val didWithoutPrefix  = kid.removePrefix("did:tdw:")
                val encodedPath  = didWithoutPrefix .substringAfter(":", missingDelimiterValue = "")

                val formattedPath = if (encodedPath .isNotEmpty()) {
                    encodedPath .replace(":", "/")
                } else {
                    "/.well-known"
                }
                val decodedPath  = URLDecoder.decode(formattedPath, "UTF-8")
                val urlPath = decodedPath .substringBefore("#")
                val resultUrl = "https://$urlPath/did.jsonl"
                processJWKFromUrl(kid,resultUrl)
            }
            else{
                null
            }
        }catch (e:Exception){
            println("Error processing TrustDIDWeb from KID: ${e.message}")
            null
        }
    }

    private suspend fun processJWKFromUrl(kid: String?, resultUrl:String?): JWK? {
        if (resultUrl != null) {
            val jwkKey = fetchJwksTDW(resultUrl = resultUrl, kid = kid)
            return convertToJWK(jwkKey)
        }
        return null
    }
    private suspend fun fetchJwksTDW(resultUrl: String, kid: String?): JwkKey? {
        return withContext(Dispatchers.IO) {
            try {
                val url = URL(resultUrl)
                val json = url.readText()
                val gson = Gson()
                val type = object : TypeToken<ArrayList<Any>>() {}.type

                val arrayList: ArrayList<Any> = gson.fromJson(json, type)
                var response: DataResponse? = null // Initialize response

                // Loop through arrayList and find the first valid DataResponse object
                for (item in arrayList) {
                    try {
                        val jsonItem = gson.toJson(item) // Convert to JSON String
                        val dataResponse = gson.fromJson(jsonItem, DataResponse::class.java)
                        if (dataResponse.value != null) {
                            response = dataResponse // Assign the first matching object
                            break // Stop the loop after finding the first match
                        }
                    } catch (e: Exception) {
                        // Ignore parsing errors and continue searching
                    }
                }

                if (response == null) return@withContext null

                val verificationMethod = response.value?.verificationMethod
                println(verificationMethod)
                if (verificationMethod != null) {
                    val matchingVerificationMethod = verificationMethod.firstOrNull { it.id == kid }

                    // If a match is found, extract the publicKeyJwk
                    if (matchingVerificationMethod != null) {
                        val publicKeyJwk = matchingVerificationMethod.publicKeyJwk
                        if (publicKeyJwk != null) {
                            // Create a JwkKey instance using your existing model
                            val jwkKey = JwkKey(
                                id = matchingVerificationMethod.id ?: "",
                                type = matchingVerificationMethod.type ?: "",
                                controller = matchingVerificationMethod.controller ?: "",
                                publicKeyJwk = publicKeyJwk
                            )
                            println("Found matching publicKeyJwk: $jwkKey")
                            return@withContext jwkKey
                        } else if (matchingVerificationMethod.publicKeyBase58 != null) {
                            val jwkKey = JwkKey(
                                id = matchingVerificationMethod.id ?: "",
                                type = matchingVerificationMethod.type ?: "",
                                controller = matchingVerificationMethod.controller ?: "",
                                publicKeyBase58 = matchingVerificationMethod.publicKeyBase58
                            )
                            println("Found matching publicKeyBase58: $jwkKey")
                            return@withContext jwkKey
                        }
                        else {
                            println("No publicKeyJwk found for the matching verification method.")
                        }
                    } else {
                        println("No matching verification method found for kid: $kid")
                    }
                } else {
                    println("No verificationMethod found in response.")
                }

                return@withContext null // Return null if no match is found
            } catch (e: Exception) {
                println(e.toString())
                return@withContext null // Return null on error
            }
        }
    }
}