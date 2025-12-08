package com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction

import com.ewc.eudi_wallet_oidc_android.models.DataResponse
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.nimbusds.jose.jwk.JWK
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URL
import java.net.URLDecoder

class ProcessWebVhFromKID {
    suspend fun processWebVerifiableHistoryFromKID(kid: String): JWK?{
        return try {
            if (kid.startsWith("did:webvh:")) {
                val didWithoutPrefix = kid.removePrefix("did:webvh:")

                // 1️⃣ Remove SCID (first segment after prefix)
                val withoutScid = didWithoutPrefix.substringAfter(":")

                // 2️⃣ Extract domain (first segment after SCID)
                val domainWithPort = withoutScid.substringBefore(":")
                val pathAfterDomain = withoutScid.substringAfter(":", "")

                // 3️⃣ Handle optional port in domain
                val domainParts = domainWithPort.split("%3A", ":")
                val domain = domainParts[0]
                val port = domainParts.getOrNull(1)

                // 4️⃣ Transform path
                val formattedPath = if (pathAfterDomain.isNotEmpty()) {
                    pathAfterDomain.replace(":", "/")
                } else {
                    ".well-known" // fallback if no path
                }

                // 5️⃣ Decode path
                val decodedPath = URLDecoder.decode(formattedPath, "UTF-8")
                val urlPath = if (decodedPath == ".well-known") "/.well-known" else decodedPath.substringBefore("#")

                // 6️⃣ Reconstruct HTTPS URL
                val resultUrl = when {
                    port != null && urlPath.startsWith("/") -> "https://$domain:$port$urlPath/did.jsonl"
                    port != null -> "https://$domain:$port/$urlPath/did.jsonl"
                    urlPath.startsWith("/") -> "https://$domain$urlPath/did.jsonl"
                    else -> "https://$domain/$urlPath/did.jsonl"
                }


                // 7️⃣ Call existing function to fetch JWK
                processJWKFromUrl(kid, resultUrl)
            } else {
                null
            }
        } catch (e: Exception) {
            println("Error processing TrustDIDWeb from KID: ${e.message}")
            null
        }
    }

    private suspend fun processJWKFromUrl(kid: String?, resultUrl:String?): JWK? {
        if (resultUrl != null) {
            val jwkKey = fetchJwksWebVh(resultUrl = resultUrl, kid = kid)
            return convertToJWK(jwkKey)
        }
        return null
    }
    private suspend fun fetchJwksWebVh(resultUrl: String, kid: String?): JwkKey? {
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
                        } else {
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