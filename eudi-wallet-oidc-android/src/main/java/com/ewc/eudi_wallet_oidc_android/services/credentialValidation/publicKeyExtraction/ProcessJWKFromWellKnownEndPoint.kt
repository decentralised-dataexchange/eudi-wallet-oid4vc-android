package com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.net.URL

class ProcessJWKFromWellKnownEndPoint {

    private val client = OkHttpClient()

    suspend fun processJWKFromWellKnownEndPoint(
        kid: String,
        iss: String
    ): JWK? = withContext(Dispatchers.IO) {
        try {
            // 1. Generate the well-known URL
            val wellKnownUrl = generateWellKnownUrl(iss) ?: return@withContext null

            // 2. HTTP GET request
            val request = Request.Builder()
                .url(wellKnownUrl)
                .get()
                .build()

            val response = client.newCall(request).execute()
            if (!response.isSuccessful) return@withContext null

            val body = response.body?.string() ?: return@withContext null
            val metadata = JSONObject(body)

            // 3. Extract jwks_uri or jwks
            val jwksUri = metadata.optString("jwks_uri", null)
            val jwks = metadata.optJSONObject("jwks")?.toString()

            // 4. Resolve JWK
            when {
                jwksUri != null ->
                    ProcessJWKFromJwksUri().processJWKFromJwksUri(kid, jwksUri)

                jwks != null ->
                    processJWKFromJwksJson(kid, jwks)

                else -> null
            }

        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    // Helper to generate well-known URL from iss
    private fun generateWellKnownUrl(iss: String): String? {
        return try {
            // Only attempt if iss starts with http:// or https://
            if (!iss.startsWith("http://") && !iss.startsWith("https://")) return null

            val url = URL(iss)
            val path = url.path.removeSuffix("/") // remove trailing '/'
            val wellKnownPath = if (path.isEmpty()) "/.well-known/jwt-vc-issuer"
            else "/.well-known/jwt-vc-issuer$path"

            "${url.protocol}://${url.host}${if (url.port != -1) ":${url.port}" else ""}$wellKnownPath"
        } catch (e: Exception) {
            null
        }
    }
    fun processJWKFromJwksJson(kid: String, jwksJson: String): JWK? {
        return try {
            val jwkSet = JWKSet.parse(jwksJson) // Parse the JWKS JSON string
            jwkSet.keys.firstOrNull { it.keyID == kid } // Find the JWK with matching kid
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
}
