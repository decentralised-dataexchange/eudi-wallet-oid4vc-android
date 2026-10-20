package com.ewc.eudi_wallet_oidc_android.services.verification.response

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessJWKFromJwksUri
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL

/**
 * OpenID4VP 1.0 section 8.3, encrypted responses: "implementations MUST use an unsigned, encrypted
 * JWT", the key comes from the client metadata `jwks`, "the JWE alg algorithm used MUST be equal
 * to the alg value of the chosen jwk", the `kid` is copied, and "the JWE enc content encryption
 * algorithm used is obtained from the encrypted_response_enc_values_supported parameter ...
 * allowing for the default value of A128GCM when not explicitly set".
 *
 * The draft names `authorization_encrypted_response_alg` and `authorization_encrypted_response_enc`
 * are read when the 1.0 ones are absent. `apu` carries the client id and `apv` the nonce, which is
 * what the ISO 18013-7 Annex B session transcript expects to find.
 */
class ResponseEncrypter {

    /**
     * @throws SubmissionException.NoEncryptionKey
     * @throws SubmissionException.EncryptionUnsupported
     * @throws SubmissionException.EncryptionFailed
     */
    suspend fun encrypt(parameters: Map<String, Any?>, request: PresentationRequest): String {
        val metadata = try {
            Gson().toJsonTree(request.clientMetaDetails).asJsonObject
        } catch (e: Exception) {
            throw SubmissionException.NoEncryptionKey()
        }
        val (key, keyAlg) = selectKey(metadata)
        val algorithm = selectAlgorithm(keyAlg, metadata)
        val encryption = selectEncryption(metadata)
        Logger.d(TAG, "Encrypting the response with $algorithm and $encryption to key ${key.keyID ?: "(no kid)"}")

        return try {
            val header = JWEHeader.Builder(algorithm, encryption)
                .keyID(key.keyID)
                .apply {
                    request.nonce?.let { agreementPartyVInfo(Base64URL.encode(it)) }
                    request.clientId?.let { agreementPartyUInfo(Base64URL.encode(it)) }
                }
                .build()
            @Suppress("UNCHECKED_CAST")
            JWEObject(header, Payload(parameters as Map<String, Any>)).apply { encrypt(ECDHEncrypter(key)) }.serialize()
        } catch (e: Exception) {
            throw SubmissionException.EncryptionFailed(e)
        }
    }

    /** The P-256 encryption key, `use: enc` first, then a key with no `use`, and its own `alg` when it names one. */
    private suspend fun selectKey(metadata: JsonObject): Pair<ECKey, String?> {
        val raw: JsonObject = metadata.get("jwks_uri")?.takeIf { it.isJsonPrimitive }?.asString?.let { uri ->
            try {
                ProcessJWKFromJwksUri().fetchJwks(jwksUri = uri, kid = null, keyUse = "enc")?.let { Gson().toJsonTree(it).asJsonObject }
            } catch (e: Exception) {
                null
            }
        } ?: metadata.getAsJsonObject("jwks")?.getAsJsonArray("keys")
            ?.map { it.asJsonObject }
            ?.filter { it.get("crv")?.takeIf { v -> !v.isJsonNull }?.asString == "P-256" }
            ?.let { keys ->
                keys.firstOrNull { it.get("use")?.takeIf { v -> !v.isJsonNull }?.asString == "enc" }
                    ?: keys.firstOrNull { it.get("use") == null || it.get("use").isJsonNull }
            }
        ?: throw SubmissionException.NoEncryptionKey()

        val key = try {
            ECKey.Builder(Curve.P_256, Base64URL.from(raw.get("x").asString), Base64URL.from(raw.get("y").asString))
                .keyID(raw.get("kid")?.takeIf { !it.isJsonNull }?.asString)
                .build()
        } catch (e: Exception) {
            throw SubmissionException.NoEncryptionKey()
        }
        return key to raw.get("alg")?.takeIf { !it.isJsonNull }?.asString
    }

    private fun selectAlgorithm(keyAlg: String?, metadata: JsonObject): JWEAlgorithm {
        val named = keyAlg?.takeIf { it.isNotBlank() }
            ?: metadata.get(DRAFT_ALG)?.takeIf { it.isJsonPrimitive }?.asString?.takeIf { it.isNotBlank() }
            ?: return JWEAlgorithm.ECDH_ES
        val algorithm = JWEAlgorithm.parse(named)
        if (algorithm !in SUPPORTED_ALGORITHMS) throw SubmissionException.EncryptionUnsupported("the key algorithm $named is not supported")
        return algorithm
    }

    private fun selectEncryption(metadata: JsonObject): EncryptionMethod {
        val supported: List<String> = when {
            metadata.has(ENC_VALUES_SUPPORTED) && metadata.get(ENC_VALUES_SUPPORTED).isJsonArray ->
                metadata.getAsJsonArray(ENC_VALUES_SUPPORTED).map { it.asString }
            metadata.has(DRAFT_ENC) && metadata.get(DRAFT_ENC).isJsonPrimitive -> listOf(metadata.get(DRAFT_ENC).asString)
            metadata.has(LEGACY_ENC_VALUES_SUPPORTED) && metadata.get(LEGACY_ENC_VALUES_SUPPORTED).isJsonArray ->
                metadata.getAsJsonArray(LEGACY_ENC_VALUES_SUPPORTED).map { it.asString }
            else -> listOf(EncryptionMethod.A128GCM.name)
        }
        val chosen = PREFERENCE.firstOrNull { it.name in supported }
            ?: throw SubmissionException.EncryptionUnsupported("none of the content encryptions $supported is supported")
        return chosen
    }

    private companion object {
        const val TAG = "ResponseEncrypter"
        const val ENC_VALUES_SUPPORTED = "encrypted_response_enc_values_supported"
        const val LEGACY_ENC_VALUES_SUPPORTED = "authorization_encrypted_response_enc_values_supported"
        const val DRAFT_ALG = "authorization_encrypted_response_alg"
        const val DRAFT_ENC = "authorization_encrypted_response_enc"
        val SUPPORTED_ALGORITHMS = setOf(JWEAlgorithm.ECDH_ES, JWEAlgorithm.ECDH_ES_A128KW, JWEAlgorithm.ECDH_ES_A256KW)
        val PREFERENCE = listOf(EncryptionMethod.A128CBC_HS256, EncryptionMethod.A128GCM, EncryptionMethod.A256GCM, EncryptionMethod.A256CBC_HS512)
    }
}
