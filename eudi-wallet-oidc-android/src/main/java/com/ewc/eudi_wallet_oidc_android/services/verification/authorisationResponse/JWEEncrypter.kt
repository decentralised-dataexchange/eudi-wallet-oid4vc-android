package com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessJWKFromJwksUri
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.crypto.ECDHEncrypter
import org.json.JSONObject

class JWEEncrypter {
    /**
     * Encrypts the given payload into a JWE using ECDH-ES + A128CBC-HS256.
     *
     * @param publicECJWK Recipient's EC public JWK (P-256 curve).
     * @param payload Map of claims to include in the JWT.
     * @return Encrypted JWT (JWE) as a compact string.
     */
    companion object {
        private const val TAG = "JWEEncrypterLog"
    }

    suspend fun encrypt(
        payload: Map<String, Any?>,
        presentationRequest: PresentationRequest
    ): String {
        Log.d(TAG, "Starting encryption process...")
        Log.d(TAG, "Payload: $payload")
        Log.d(
            TAG,
            "PresentationRequest.clientMetaDetails: ${presentationRequest.clientMetaDetails}"
        )

        val gson = Gson()
        val clientMetadataJson = gson.toJsonTree(presentationRequest.clientMetaDetails).asJsonObject
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
            val matchedKey = keysArray.find {
                it.asJsonObject.get("crv").asString == "P-256"
            }?.asJsonObject

            if (matchedKey == null) {
                Log.e(TAG, "No P-256 curve key found in client metadata.")
            } else {
                Log.d(TAG, "Found P-256 key: $matchedKey")
            }

            matchedKey
                ?: throw IllegalArgumentException("No P-256 curve key found in client metadata")
        }

        Log.d(TAG, "Creating ECKey with kid: ${p256Key?.get("kid")?.asString}")

        val publicECJWK = ECKey.Builder(
            Curve.P_256,
            Base64URL.from(p256Key?.get("x")?.asString),
            Base64URL.from(p256Key?.get("y")?.asString)
        )
            .keyID(p256Key?.get("kid")?.asString)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .build()

        Log.d(TAG, "ECKey created: $publicECJWK")
        val encSupported = clientMetadataJson
            .getAsJsonArray("encrypted_response_enc_values_supported")
            ?.map { it.asString }
            ?: emptyList()

        Log.d(TAG, "Verifier supported enc methods: $encSupported")

        val encryptionMethod = selectEncryptionMethod(encSupported)

        Log.d(TAG, "Selected encryption method: $encryptionMethod")


        val header = JWEHeader.Builder(JWEAlgorithm.ECDH_ES, encryptionMethod)
            .keyID(p256Key?.get("kid")?.asString)
            .agreementPartyVInfo(Base64URL.encode(presentationRequest.nonce))
            .agreementPartyUInfo(Base64URL.encode(presentationRequest.clientId))
            .build()

        Log.d(TAG, "JWEHeader created: $header")

        val encryptedJWT = JWEObject(header, Payload(payload))
        val encryptor = ECDHEncrypter(publicECJWK)

        Log.d(TAG, "Encrypting JWEObject...")
        encryptedJWT.encrypt(encryptor)

        val serialized = encryptedJWT.serialize()
        Log.d(TAG, "Encryption complete. Serialized JWE: $serialized")

        return serialized
    }
    suspend fun encrypt(
        payload: Map<String, Any?>,
        jwk: JsonObject?
    ): String {

        val publicECJWK = ECKey.Builder(
            Curve.P_256,
            Base64URL.from(jwk?.get("x")?.asString),
            Base64URL.from(jwk?.get("y")?.asString)
        )
            .keyID(jwk?.get("kid")?.asString)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .build()

        Log.d(TAG, "ECKey created: $publicECJWK")

        val header = JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128CBC_HS256)
            .keyID(jwk?.get("kid")?.asString)
            .build()

        Log.d(TAG, "JWEHeader created: $header")

        val encryptedJWT = JWEObject(header, Payload(payload))
        val encryptor = ECDHEncrypter(publicECJWK)

        Log.d(TAG, "Encrypting JWEObject...")
        encryptedJWT.encrypt(encryptor)

        val serialized = encryptedJWT.serialize()
        Log.d(TAG, "Encryption complete. Serialized JWE: $serialized")

        return serialized
    }

    fun checkAndEncrypt(
        presentationRequest: PresentationRequest,
    ): Boolean {

        var hasAlg = false
        var hasEnc = false
        presentationRequest.clientMetaDetails?.let {
            hasAlg = (it as? Map<*, *>)?.let { map ->
                JSONObject(map.toMap()).let { json ->
                    json.has("authorization_encrypted_response_alg") && json.getString("authorization_encrypted_response_alg") == "ECDH-ES"
                }
            } ?: false
            hasEnc = (it as? Map<*, *>)?.let { map ->
                JSONObject(map.toMap()).let { json ->
                    json.has("authorization_encrypted_response_enc") && json.getString("authorization_encrypted_response_enc") == "A128CBC-HS256"
                }
            } ?: false
        }

        val requiresEncryption =
            hasAlg && hasEnc && presentationRequest.responseMode == "direct_post.jwt"

        return requiresEncryption

    }

    private fun toEncryptionMethod(enc: String): EncryptionMethod? =
        when (enc) {
            "A128CBC-HS256" -> EncryptionMethod.A128CBC_HS256
            "A128GCM" -> EncryptionMethod.A128GCM
            "A256GCM" -> EncryptionMethod.A256GCM
            else -> null
        }
    private fun selectEncryptionMethod(
        supported: List<String>
    ): EncryptionMethod {
        val preferenceOrder = listOf(
            "A128CBC-HS256",
            "A128GCM",
            "A256GCM"
        )

        val selected = preferenceOrder
            .firstOrNull { it in supported }
            ?: throw IllegalArgumentException(
                "No supported encryption method found. Verifier supports: $supported"
            )

        return toEncryptionMethod(selected)
            ?: throw IllegalStateException("Unsupported enc method: $selected")
    }


}