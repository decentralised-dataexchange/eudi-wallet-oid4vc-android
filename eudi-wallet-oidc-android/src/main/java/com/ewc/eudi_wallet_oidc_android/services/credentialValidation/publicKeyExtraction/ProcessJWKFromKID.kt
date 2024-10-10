package com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL

class ProcessJWKFromKID {
    fun processJWKFromKID(kid: String): JWK? {
        return try {
            // Ensure the kid starts with "did:jwk"
            if (kid.startsWith("did:jwk:")) {
                // Extract the Base64URL-encoded JWK
                val jwkString = kid.removePrefix("did:jwk:")

                // Decode the JWK JSON
                val decodedJwkJson = String(Base64URL(jwkString).decode())

                // Parse the JWK using Nimbus library
                val jwk = JWK.parse(decodedJwkJson)
                jwk
            } else {
                throw IllegalArgumentException("Invalid DID format for JWK")
            }
        } catch (e: Exception) {
            // Handle any exceptions that occur during parsing
            println("Error processing JWK from KID: ${e.message}")
            null
        }
    }
}