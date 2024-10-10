package com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction

import com.ewc.eudi_wallet_oidc_android.models.JwkKey
import com.ewc.eudi_wallet_oidc_android.models.JwksResponse
import com.google.gson.Gson
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
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
    suspend fun fetchJwks(jwksUri: String, kid: String?): JwkKey? {
        return withContext(Dispatchers.IO) {
            try {
                val url = URL(jwksUri)
                val json = url.readText()
                // Parse JSON into JwksResponse object
                val jwksResponse =  Gson().fromJson(json, JwksResponse::class.java)

                // Find the JWK with "use" = "sig"
                var jwkKey = jwksResponse.keys.firstOrNull { it.use == "sig" }

                // If no "sig" key is found, find by kid
                if (jwkKey == null && kid != null) {
                    jwkKey = jwksResponse.keys.firstOrNull { it.kid == kid }
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
    fun convertToJWK(jwkKey: JwkKey?): JWK? {
        return jwkKey?.let {
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
    }

}