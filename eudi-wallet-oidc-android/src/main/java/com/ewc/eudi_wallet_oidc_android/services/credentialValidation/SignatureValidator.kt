package com.ewc.eudi_wallet_oidc_android.services.credentialValidation

import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessEbsiJWKFromKID
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessJWKFromJwksUri
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessJWKFromKID
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessKeyJWKFromKID
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessWebJWKFromKID
import com.ewc.eudi_wallet_oidc_android.services.exceptions.SignatureException
import com.ewc.eudi_wallet_oidc_android.services.utils.X509SanRequestVerifier
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey

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
        var errorMessage = ""
        try {
            jwt?.let { // Null-safe check: proceed if jwt is not null
                val jwsObject = JWSObject.parse(jwt) // Parse the JWT string to a JWSObject
                val header = jwsObject.header // Retrieve the header from the parsed JWT
                val kid = header.keyID // Extract the 'kid' (key ID) from the JWT header
                val algorithm = jwsObject.header.algorithm
                val x5c = jwsObject.header.toJSONObject()

                var x5cValid = false // Track x5c validation result
                if (x5c.contains("x5c")) {
                    val x5cChain: List<String>? = X509SanRequestVerifier.instance.extractX5cFromJWT(jwt)
                    if (x5cChain != null) {
                        x5cValid = X509SanRequestVerifier.instance.validateSignatureWithCertificate(jwt, x5cChain, algorithm)
                        if (!x5cValid) errorMessage = "JWT signature x5c invalid or cannot be validated"
                    }
                }

                // If x5c validation is successful, return true immediately
                if (x5cValid) return true

                // If x5c validation failed, proceed with kid-based validation
                val responseList: MutableList<JWK> = mutableListOf()
                if (kid != null && kid.startsWith("did:key:z")){
                    ProcessKeyJWKFromKID().processKeyJWKFromKID(kid, algorithm)?.let { jwk ->
                        responseList.add(jwk) // Only add if not null
                    }
                }
                if (kid != null && kid.startsWith("did:ebsi:z")){
                    ProcessEbsiJWKFromKID().processEbsiJWKFromKID(kid)?.let { jwk ->
                        responseList.add(jwk)
                    }
                }
                if (kid != null && kid.startsWith("did:jwk")){
                    ProcessJWKFromKID().processJWKFromKID(kid)?.let { jwk ->
                        responseList.add(jwk)
                    }
                }
                if (kid != null && kid.startsWith("did:web")){
                    ProcessWebJWKFromKID().processWebJWKFromKID(kid)?.let {jwk ->
                        responseList.add(jwk)
                    }
                }
                if (kid != null && jwksUri!=null) {
                    ProcessJWKFromJwksUri().processJWKFromJwksUri(kid, jwksUri)?.let { jwk ->
                        responseList.add(jwk)
                    }
                }
                // If a valid JWK response is received, verify the JWT signature
                for (jwk in responseList) {
                    val splitJwt = try {
                        jwt.split("~")[0] // Try to remove any tilde (~) character in the JWT signature
                    } catch (e: Exception) {
                        jwt // If split fails, use the original JWT
                    }

                    // Verify the JWT signature with the current JWK
                    if (verifyJwtSignature(splitJwt, jwk.toJSONString())) {
                        return true // ✅ If any key is valid, return immediately
                    }
                }
                if (!x5c.contains("x5c")) {
                    errorMessage = "JWT signature invalid"
                }
                // ❌ If both x5c and kid-based verification fail, throw an exception
                throw SignatureException(errorMessage)// Throw an exception if JWK response is null

            } ?: throw SignatureException("JWT signature invalid") // Handle the case where JWT is null

        } catch (e: IllegalArgumentException) {
            // Handle any IllegalArgumentException thrown during the process
            if (e.message?.contains("x5c") == true) {
                throw e // Rethrow if it's related to 'x5c'
            }
            throw SignatureException("JWT signature invalid") // Wrap the exception into a SignatureException
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
            val jwk = JWK.parse(jwkJson)

            // Parse the JWT string into a JWS object (JSON Web Signature)
            val jwsObject = JWSObject.parse(jwt)

            // Get the algorithm specified in the JWS header
            val algorithm = jwsObject.header.algorithm

            // Create the appropriate verifier based on the algorithm used in the JWS header
            val verifier: JWSVerifier = when (algorithm) {
                // For ES256 (ECDSA using P-256 curve and SHA-256), create an ECDSAVerifier
                JWSAlgorithm.ES256 -> {
                    if (jwk is ECKey) {
                        ECDSAVerifier(jwk)  // Use the ECKey directly
                    } else {
                        throw JOSEException("JWK is not ECKey for algorithm $algorithm")
                    }
                }

                // For ES384 (ECDSA using P-384 curve and SHA-384), create an ECDSAVerifier
                JWSAlgorithm.ES384 -> {
                    if (jwk is ECKey) {
                        ECDSAVerifier(jwk)  // Use the ECKey directly
                    } else {
                        throw JOSEException("JWK is not ECKey for algorithm $algorithm")
                    }
                }

                // For ES512 (ECDSA using P-521 curve and SHA-512), create an ECDSAVerifier
                JWSAlgorithm.ES512 -> {
                    if (jwk is ECKey) {
                        ECDSAVerifier(jwk)  // Use the ECKey directly
                    } else {
                        throw JOSEException("JWK is not ECKey for algorithm $algorithm")
                    }
                }

                // For RS256 (RSA algorithm), create an RSASSAVerifier
                JWSAlgorithm.RS256 -> {
                    if (jwk is RSAKey) {
                        RSASSAVerifier(jwk)  // Use the RSAKey directly
                    } else {
                        throw JOSEException("JWK is not RSAKey for algorithm $algorithm")
                    }
                }

                // For RS384 (RSA algorithm), create an RSASSAVerifier
                JWSAlgorithm.RS384 -> {
                    if (jwk is RSAKey) {
                        RSASSAVerifier(jwk)  // Use the RSAKey directly
                    } else {
                        throw JOSEException("JWK is not RSAKey for algorithm $algorithm")
                    }
                }

                // For RS512 (RSA algorithm), create an RSASSAVerifier
                JWSAlgorithm.RS512 -> {
                    if (jwk is RSAKey) {
                        RSASSAVerifier(jwk)  // Use the RSAKey directly
                    } else {
                        throw JOSEException("JWK is not RSAKey for algorithm $algorithm")
                    }
                }

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

//    @Throws(IllegalArgumentException::class)
//    private fun verifyJwtSignature(jwt: String, jwkJson: String): Boolean {
//        try {
//            // Parse the JWK (JSON Web Key) from the JSON string
//           // val jwk = ECKey.parse(jwkJson)
//            // Parse the JWK (JSON Web Key) from the JSON string
//            val jwk = JWK.parse(jwkJson)
//
//            // Parse the JWT string into a JWS object (JSON Web Signature)
//            val jwsObject = JWSObject.parse(jwt)
//
//            // Get the algorithm specified in the JWS header
//            val algorithm = jwsObject.header.algorithm
//
//            // Create the appropriate verifier based on the algorithm used in the JWS header
//            val verifier: JWSVerifier = when (algorithm) {
//                // For ES256 (ECDSA using P-256 curve and SHA-256), create an ECDSAVerifier
//                JWSAlgorithm.ES256 -> ECDSAVerifier(jwk.toECKey())
//
//                // For ES384 (ECDSA using P-384 curve and SHA-384), create an ECDSAVerifier
//                JWSAlgorithm.ES384 -> ECDSAVerifier(jwk.toECKey())
//
//                // For ES512 (ECDSA using P-521 curve and SHA-512), create an ECDSAVerifier
//                JWSAlgorithm.ES512 -> ECDSAVerifier(jwk.toECKey())
//                // Throw an exception if the algorithm is unsupported
//                else -> throw JOSEException("Unsupported JWS algorithm $algorithm")
//            }
//
//            // Verify the signature of the JWS using the appropriate verifier
//            return jwsObject.verify(verifier)
//        } catch (e: Exception) {
//            // Print the stack trace for debugging purposes
//            e.printStackTrace()
//
//            // Throw an IllegalArgumentException if signature verification fails or any error occurs
//            throw IllegalArgumentException("Invalid signature")
//        }
//    }

}