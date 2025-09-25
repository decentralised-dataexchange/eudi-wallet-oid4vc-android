package com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction

import com.google.gson.Gson
import com.mediaparkpk.base58android.Base58
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.util.Base64URL
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class ProcessWebJWKFromKID {

    /**
     * Processes a JWK from a Web DID and retrieves it using the constructed JWKS URI.
     *
     * @param did The DID (Decentralized Identifier) starting with "did:web".
     * @return The JWK object if found; otherwise, null.
     */
    suspend fun processWebJWKFromKID(did: String?): JWK? {
        // Ensure that the DID is valid and starts with "did:web"
        if (did == null || !did.startsWith("did:web:")) {
            return null // Return null if DID is null or not a web DID
        }

        // Remove the "did:web:" prefix and split by "#" to handle the path
        val cleanedDid = did.removePrefix("did:web:")
        val pathAndFragment = cleanedDid.split("#")[0] // Get the part before the fragment if it exists

        // Construct the JWKS URI by replacing ":" with "/" and appending "/did.json"
        val parts = pathAndFragment.split(":")
        val domain = parts.first() // The first part is the domain
        val path = parts.drop(1).joinToString("/") // Join remaining parts with "/"

        // Construct the full JWKS URI
        val jwksUri = if (path.isNotEmpty()) {
            "https://$domain/$path/did.json" // Use the path if available
        } else {
            "https://$domain/.well-known/did.json" // Use the default path if no additional path is given
        }
        val jwkKey =fetchJwks(jwksUri =jwksUri, kid = did)
        val converted = convertToJWK(jwkKey)


        // Fetch the JWK using the constructed JWKS URI
        return converted// Call your existing fetchJwks function
    }

}
// Define your data classes
data class JwksResponse(
    val verificationMethod: List<JwkKey>
)

data class JwkKey(
    val id: String,
    val type: String,
    val controller: String,
    val publicKeyJwk: PublicKeyJwk?=null,
    val publicKeyBase58: String? = null
)

data class PublicKeyJwk(
    val kty: String,
    val use: String,
    val crv: String,
    val x: String,
    val y: String
)

suspend fun fetchJwks(jwksUri: String, kid: String?): JwkKey? {
    return withContext(Dispatchers.IO) {
        try {
            val url = URL(jwksUri)
            val json = url.readText()
            // Parse JSON into JwksResponse object
            val jwksResponse = Gson().fromJson(json, JwksResponse::class.java)

            // Find the JWK with "use" = "sig"
            var jwkKey = jwksResponse.verificationMethod.firstOrNull { it.publicKeyJwk?.use == "sig" }

            // If no "sig" key is found, find by kid
            if (jwkKey == null && kid != null) {
                jwkKey = jwksResponse.verificationMethod.firstOrNull { it.id == kid }
            }
            // If still null, pick the first key with Base58
            if (jwkKey == null && kid != null) {
                jwkKey = jwksResponse.verificationMethod.firstOrNull { it.publicKeyBase58 != null }
            }
            return@withContext jwkKey
        } catch (e: Exception) {
            println(e.toString())
            return@withContext null
        }
    }
}
fun convertToJWK(jwkKey: JwkKey?): JWK? {
    return jwkKey?.let {
        val publicKeyJwk = it.publicKeyJwk // Access the nested publicKeyJwk

        // Case 1: EC keys
        if (publicKeyJwk != null && publicKeyJwk.x != null && publicKeyJwk.y != null) {
            val curve = when (publicKeyJwk.crv) {
                "P-256" -> Curve.P_256
                "P-384" -> Curve.P_384
                "P-521" -> Curve.P_521
                else -> throw IllegalArgumentException("Unsupported curve: ${publicKeyJwk.crv}")
            }

            return ECKey.Builder(curve, Base64URL.from(publicKeyJwk.x), Base64URL.from(publicKeyJwk.y))
                .keyID(it.id)
                .build()
        }

        // Case 2: Ed25519 from Base58
        jwkKey.publicKeyBase58?.let { base58 ->
            val pubBytes = Base58.decode(base58)
            val x = Base64URL.encode(pubBytes)
            return OctetKeyPair.Builder(Curve.Ed25519, x)
                .keyID(it.id)
                .build()
        }
        null
    }
}