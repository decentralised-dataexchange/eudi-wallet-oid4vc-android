package com.ewc.eudi_wallet_oidc_android.services.credentialValidation

import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessEbsiJWKFromKID
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessJWKFromJwksUri
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessJWKFromKID
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessKeyJWKFromKID
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessWebJWKFromKID
import com.ewc.eudi_wallet_oidc_android.services.exceptions.SignatureException
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSVerifier

class SignatureValidator {

    /**
     * Validates the signature of a JWT using a JWK fetched either from
     *    Kid or JWKS URI present in Authorisation configuration.
     *
     * @param jwt
     * @param jwksUri
     * @return
     *
     * Throws SignatureException if validation fails
     */
    @Throws(SignatureException::class) // Declare that this function might throw a SignatureException
    suspend fun validateSignature(jwt: String?, jwksUri: String? = null): Boolean { // Suspended function to validate JWT signature, allowing optional JWKS URI
        return try {
            jwt?.let { // Null-safe check: proceed if jwt is not null
                val jwsObject = JWSObject.parse(jwt) // Parse the JWT string to a JWSObject
                val header = jwsObject.header // Retrieve the header from the parsed JWT
                val kid = header.keyID // Extract the 'kid' (key ID) from the JWT header
                val algorithm = jwsObject.header.algorithm // Extract the algorithm used in the JWT header

                // Check the format of 'kid' and process it accordingly
                val response = if (kid != null && kid.startsWith("did:key:z")) { // Check if 'kid' starts with "did:key:z"
                    ProcessKeyJWKFromKID().processKeyJWKFromKID(kid, algorithm) // Process as a key-based DID JWK (Decentralized Identifier)
                } else if (kid != null && kid.startsWith("did:ebsi:z")) { // Check if 'kid' starts with "did:ebsi:z"
                    ProcessEbsiJWKFromKID().processEbsiJWKFromKID(kid) // Process as an EBSI-based DID JWK
                } else if (kid != null && kid.startsWith("did:jwk")) { // Check if 'kid' starts with "did:jwk"
                    ProcessJWKFromKID().processJWKFromKID(kid) // Process as a JWK (JSON Web Key) DID
                } else if(kid !=null && kid.startsWith("did:web")){
                    ProcessWebJWKFromKID().processWebJWKFromKID(kid)
                }
                else {
                    ProcessJWKFromJwksUri().processJWKFromJwksUri(kid, jwksUri) // Process JWK using the provided JWKS URI
                }

                // If a valid JWK response is received, verify the JWT signature
                if (response != null) {
                    val isSignatureValid = verifyJwtSignature(jwt, response.toJSONString()) // Verify signature using the JWK response
                    isSignatureValid // Return the result of the signature verification
                } else {
                    throw SignatureException("Invalid signature") // Throw an exception if JWK response is null
                }
            } ?: throw SignatureException("Invalid signature") // Handle the case where JWT is null
        } catch (e: IllegalArgumentException) { // Catch any IllegalArgumentException thrown during the process
            throw SignatureException("Invalid signature") // Wrap the exception into a SignatureException
        }
    }

    /**
     * Verifies the signature of a JWT using a JWK provided as JSON.
     *
     * @param jwt
     * @param jwkJson
     * @return
     */
    @Throws(IllegalArgumentException::class)
    private fun verifyJwtSignature(jwt: String, jwkJson: String): Boolean {
        try {
            // Parse the JWK (JSON Web Key) from the JSON string
            val jwk = ECKey.parse(jwkJson)

            // Parse the JWT string into a JWS object (JSON Web Signature)
            val jwsObject = JWSObject.parse(jwt)

            // Get the algorithm specified in the JWS header
            val algorithm = jwsObject.header.algorithm

            // Create the appropriate verifier based on the algorithm used in the JWS header
            val verifier: JWSVerifier = when (algorithm) {
                // For ES256 (ECDSA using P-256 curve and SHA-256), create an ECDSAVerifier
                JWSAlgorithm.ES256 -> ECDSAVerifier(jwk.toECKey())

                // For ES384 (ECDSA using P-384 curve and SHA-384), create an ECDSAVerifier
                JWSAlgorithm.ES384 -> ECDSAVerifier(jwk.toECKey())

                // For ES512 (ECDSA using P-521 curve and SHA-512), create an ECDSAVerifier
                JWSAlgorithm.ES512 -> ECDSAVerifier(jwk.toECKey())

                // Throw an exception if the algorithm is unsupported
                else -> throw JOSEException("Unsupported JWS algorithm $algorithm")
            }

            // Verify the signature of the JWS using the appropriate verifier
            return jwsObject.verify(verifier)
        } catch (e: Exception) {
            // Print the stack trace for debugging purposes
            e.printStackTrace()

            // Throw an IllegalArgumentException if signature verification fails or any error occurs
            throw IllegalArgumentException("Invalid signature")
        }
    }

}