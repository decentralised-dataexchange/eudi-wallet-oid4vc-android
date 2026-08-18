package com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessJWKFromJwksUri
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL

object VerifierJwk {

    const val TAG = "VerifierJwkLog"
    suspend fun deriveVerifiersJWKFromClientMetadata(
        clientMetadataJson: JsonObject,
        jweAlgorithm: JWEAlgorithm
    ): ECKey? {
        val jwksUri = clientMetadataJson.getAsJsonPrimitive("jwks_uri")?.asString
        Log.d(TAG, "JWKS URI: $jwksUri")

        val p256Key = if (jwksUri != null) {
            Log.d(TAG, "Fetching key from JWKS URI...")
            ProcessJWKFromJwksUri().fetchJwks(
                jwksUri = jwksUri,
                kid = null,
                keyUse = "enc"
            )?.let {
                Log.d(TAG, "Fetched key: $it")
                Gson().toJsonTree(it).asJsonObject
            }
        } else {
            Log.d(TAG, "Extracting key from embedded JWKS...")
            val jwksJson = clientMetadataJson.getAsJsonObject("jwks")
            val keysArray = jwksJson.getAsJsonArray("keys")
            val p256Keys = keysArray
                .map { it.asJsonObject }
                .filter { k -> k.get("crv")?.takeIf { !it.isJsonNull }?.asString == "P-256" }
            // The response is ENCRYPTED to this key, so the encryption key must
            // be chosen: 'use: enc' first, then a key that declares no use.
            // A 'sig' key is never acceptable — verifiers (e.g. BankID) publish
            // both in one set, and the first P-256 key may be the signing key.
            val matchedKey = p256Keys.firstOrNull { k ->
                k.get("use")?.takeIf { !it.isJsonNull }?.asString == "enc"
            } ?: p256Keys.firstOrNull { k ->
                k.get("use") == null || k.get("use").isJsonNull
            }

            if (matchedKey == null) {
                Log.e(TAG, "No P-256 encryption key (use=enc) found in client metadata.")
            } else {
                Log.d(TAG, "Found P-256 encryption key: $matchedKey")
            }

            matchedKey
                ?: throw IllegalArgumentException("No P-256 encryption key found in client metadata")
        }

        val publicECJWK = ECKey.Builder(
            Curve.P_256,
            Base64URL.from(p256Key?.get("x")?.asString),
            Base64URL.from(p256Key?.get("y")?.asString)
        )
            .keyID(p256Key?.get("kid")?.asString)
            .algorithm(jweAlgorithm)
            .build()

        return publicECJWK
    }

    fun deriveJWEAlgorithmFromClientMetadata(clientMetadataJson: JsonObject): JWEAlgorithm {
        val jweAlgorithm: JWEAlgorithm =
            clientMetadataJson
                .getAsJsonPrimitive("authorization_encrypted_response_alg")
                ?.asString
                ?.takeIf { it.isNotBlank() }
                ?.let { alg ->
                    val parsedAlg = try {
                        JWEAlgorithm.parse(alg)
                    } catch (e: Exception) {
                        throw IllegalArgumentException("Unsupported JWE encryption algorithm.", e)
                    }

                    if (parsedAlg != JWEAlgorithm.ECDH_ES) {
                        throw IllegalArgumentException("The specified JWE encryption algorithm is not supported.")
                    }

                    parsedAlg
                }
                ?: JWEAlgorithm.ECDH_ES

        Log.d(TAG, "Selected JWE algorithm: $jweAlgorithm")

        return jweAlgorithm
    }
}