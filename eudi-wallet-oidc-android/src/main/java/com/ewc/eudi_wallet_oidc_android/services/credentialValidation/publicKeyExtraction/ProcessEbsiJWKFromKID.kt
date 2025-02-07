package com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction

import com.ewc.eudi_wallet_oidc_android.models.DIDDocument
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import retrofit2.Response
import java.text.ParseException

class ProcessEbsiJWKFromKID {
    // This function fetches and processes the DID Document, and extracts the P-256 JWK if present.
    suspend fun processEbsiJWKFromKID(kid: String?): ECKey? {
        return try {
            // Validate DID format
            if (kid == null || !kid.startsWith("did:ebsi:z")) {
                throw IllegalArgumentException("Invalid DID format")
            }

            val service = ApiManager.api.getService()
                ?: throw IllegalStateException("API service not available")

            // First attempt with conformance API
            val did = runCatching { kid?.split("#")?.getOrNull(0) }.getOrElse { kid }
            var response: Response<DIDDocument>? = service.ebsiDIDResolver(
                "https://api-conformance.ebsi.eu/did-registry/v5/identifiers/$did"
            )
            if (response != null && response.isSuccessful) {
                val ecKey = extractJWK(response.body(), kid)
                if (ecKey!=null)
                    return ecKey
            }
            // If the conformance API call is not successful, attempt the pilot API

            response = service.ebsiDIDResolver(
                "https://api-pilot.ebsi.eu/did-registry/v5/identifiers/$did"
            )
            if (response != null && response.isSuccessful) {
                val ecKey = extractJWK(response.body(), kid)
                if (ecKey!=null)
                    return ecKey
            }
            throw IllegalStateException("Failed to fetch DID Document from both endpoints")
        } catch (e: Exception) {
            // Handle errors, possibly log or rethrow as needed
            println("Error processing DID: ${e.message}")
            null
        }
    }

    private fun extractJWK(didDocument: DIDDocument?, kid: String): ECKey? {
        if (didDocument == null)
            return null
        return try {
            // Iterate through each verification method
            for (method in didDocument.verificationMethods) {
                try {
                    val publicKeyJwk = method.publicKeyJwk

                    // Check if 'crv' is 'P-256'
                    if (method.id == kid && publicKeyJwk.crv == "P-256") {
                        // Convert the JSON JWK to a Nimbus JWK
                        val jwk = JWK.parse(
                            """{
                            "kty": "${publicKeyJwk.kty}",
                            "crv": "${publicKeyJwk.crv}",
                            "x": "${publicKeyJwk.x}",
                            "y": "${publicKeyJwk.y}"
                        }"""
                        )
                        if (jwk is ECKey) {
                            return jwk
                        }
                    }
                } catch (e: ParseException) {
                    // Handle JWK parsing exceptions
                    println("Error parsing JWK: ${e.message}")
                }
            }

            // Return null if no matching JWK is found
            null
        } catch (e: Exception) {
            // Handle any unexpected exceptions
            println("Error processing DID document: ${e.message}")
            null
        }
    }


}