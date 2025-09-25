package com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction

import com.ewc.eudi_wallet_oidc_android.models.JwkKey
import com.ewc.eudi_wallet_oidc_android.models.JwksResponse
import com.google.gson.Gson
import com.mediaparkpk.base58android.Base58
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URL

class ProcessJWKFromJwksUri {
    /**
     * Processes a JWK from a JWKS (JSON Web Key Set) URI.
     *
     * @param kid
     * @param jwksUri
     * @return
     */
    suspend fun processJWKFromJwksUri(kid: String?, jwksUri:String?): JWK? {
        if (jwksUri != null) {
            val jwkKey = fetchJwks(jwksUri =jwksUri, kid = kid)
            return convertToJWK(jwkKey)
        }
        return null
    }
    /**
     * Fetches a JwkKey object from a specified JWKS (JSON Web Key Set) URI.
     *
     * @param jwksUri
     * @param kid
     * @return
     */
    suspend fun fetchJwks(jwksUri: String, kid: String?,keyUse: String?="sig"): JwkKey? {
        return withContext(Dispatchers.IO) {
            try {
                val url = URL(jwksUri)
                val json = url.readText()
                // Parse JSON into JwksResponse object
                val jwksResponse =  Gson().fromJson(json, JwksResponse::class.java)

                // Find the JWK with "use" = "sig"
                var jwkKey = jwksResponse.keys.firstOrNull { it.use == keyUse }

                // If no "sig" key is found, find by kid
                if (jwkKey == null) {
                    jwkKey = if (kid != null) {
                        jwksResponse.keys.firstOrNull { it.kid == kid }
                    } else {
                        jwksResponse.keys.firstOrNull()
                    }
                }
                // After obtaining jwkKey
                if (jwkKey != null && jwkKey.kty == "OKP" && jwkKey.x.isNullOrEmpty()) {
                    // Suppose your API provides the Base58 public key in a field called publicKeyBase58
                    // You would decode it and assign to x
                    jwkKey.x = Base64URL.encode(Base58.decode(jwkKey.publicKeyBase58)).toString()
                }


                return@withContext jwkKey
            } catch (e: Exception) {
                println(e.toString())
                return@withContext null
            }
        }
    }
    /**
     * Converts a JwkKey object to a JWK (JSON Web Key).
     *
     * @param jwkKey The JwkKey object.
     * @return The JWK object or null if jwkKey is null.
     */
//    fun convertToJWK(jwkKey: JwkKey?): JWK? {
//        return jwkKey?.let {
//            val curve = when (it.crv) {
//                "P-256" -> Curve.P_256
//                "P-384" -> Curve.P_384
//                "P-521" -> Curve.P_521
//                else -> throw IllegalArgumentException("Unsupported curve: ${it.crv}")
//            }
//
//            ECKey.Builder(curve, Base64URL.from(it.x), Base64URL.from(it.y))
//                .keyID(it.kid)
//                .build()
//        }
//    }
    private fun convertToJWK(jwkKey: JwkKey?): JWK? {
        return jwkKey?.let {
            when (it.kty) {
                "EC" -> {
                    // Handle Elliptic Curve keys
                    val curve = when (it.crv) {
                        "P-256" -> Curve.P_256
                        "P-384" -> Curve.P_384
                        "P-521" -> Curve.P_521
                        else -> throw IllegalArgumentException("Unsupported curve: ${it.crv}")
                    }

                    ECKey.Builder(curve, Base64URL.from(it.x), Base64URL.from(it.y))
                        .keyID(it.kid)
                        .build()
                }
                "RSA" -> {
                    // Handle RSA keys
                    if (it.n == null || it.e == null) {
                        throw IllegalArgumentException("RSA keys must have 'n' (modulus) and 'e' (exponent) parameters.")
                    }

                    RSAKey.Builder(Base64URL.from(it.n), Base64URL.from(it.e))
                        .keyID(it.kid)
                        .build()
                }

                "OKP" -> {
                    // Ed25519 keys
                    OctetKeyPair.Builder(Curve.Ed25519, Base64URL.from(it.x))
                        .keyID(it.kid)
                        .build()
                }
                else -> throw IllegalArgumentException("Unsupported key type: ${it.kty}")
            }
        }
    }


}