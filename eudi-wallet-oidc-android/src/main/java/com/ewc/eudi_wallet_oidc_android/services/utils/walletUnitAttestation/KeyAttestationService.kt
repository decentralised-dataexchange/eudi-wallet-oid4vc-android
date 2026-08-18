package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.KeyAttestationRequest
import com.ewc.eudi_wallet_oidc_android.models.KeyAttestationResponse
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Date

/**
 * ARF TS3 v1.5 Key Attestation (KA).
 *
 * The main flow mints the KA on-device: the KA carries the same c_nonce as the
 * credential-request proof, so it works with any issuer and needs no
 * wallet-provider round-trip. The wallet-provider endpoint is exposed as a thin
 * optional API — its KA is only usable when the credential issuer IS the
 * wallet-provider organisation, because the KA nonce must match the proof
 * nonce and the provider validates the nonce against its own 60-second store.
 */
object KeyAttestationService {
    const val TAG = "KeyAttestation"

    private const val KA_TYP = "key-attestation+jwt"
    private const val KEY_POP_TYP = "key-pop+jwt"

    /**
     * Reads proof_types_supported.jwt.key_attestations_required for the
     * credential configuration matching the given type, from the raw issuer
     * metadata. Null when the issuer does not require a key attestation.
     */
    fun getRequirement(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?
    ): Map<String, Any>? {
        if (issuerConfig == null || type.isNullOrEmpty()) return null
        return try {
            val credentialsSupported = issuerConfig.credentialsSupported ?: return null
            val matching: Map<*, *>? = when (credentialsSupported) {
                is Map<*, *> -> credentialsSupported[type] as? Map<*, *>
                is List<*> -> credentialsSupported.filterIsInstance<Map<*, *>>()
                    .find { (it["id"] as? String)?.contains(type) == true }
                else -> null
            }
            val proofTypes = matching?.get("proof_types_supported") as? Map<*, *> ?: return null
            val jwtProof = proofTypes["jwt"] as? Map<*, *> ?: return null
            @Suppress("UNCHECKED_CAST")
            jwtProof["key_attestations_required"] as? Map<String, Any>
        } catch (e: Exception) {
            Log.e(TAG, "Failed to read key_attestations_required: ${e.message}")
            null
        }
    }

    fun isRequired(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?
    ): Boolean = getRequirement(issuerConfig, type) != null

    /**
     * The KA that goes on a credential-request proof: a pre-minted (hardware)
     * KA wins; otherwise the software tier is minted here with the SAME
     * c_nonce as the proof. Null when no KA is wanted or possible.
     */
    fun forProof(
        preMinted: String?,
        attach: Boolean,
        bindingKey: JWK?,
        cNonce: String?
    ): String? {
        return preMinted
            ?: if (attach && bindingKey is ECKey) {
                mintSoftwareKeyAttestation(bindingKey, cNonce)
            } else null
    }

    /**
     * Software tier ("software_self_attested"): the KA is self-signed by the
     * binding key. The server forces the software assurance labels; this tier
     * does not satisfy an iso_18045_high (enforceWUA) requirement.
     */
    fun mintSoftwareKeyAttestation(
        bindingKey: ECKey,
        cNonce: String?
    ): String? {
        return try {
            val now = Date()
            val header = JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType(KA_TYP))
                .build()
            val claims = JWTClaimsSet.Builder()
                .issueTime(now)
                .expirationTime(Date(now.time + 12 * 60 * 60 * 1000))
                .claim("attested_keys", listOf(bindingKey.toPublicJWK().toJSONObject()))
                .apply { if (!cNonce.isNullOrEmpty()) claim("nonce", cNonce) }
                .build()
            val jwt = SignedJWT(header, claims)
            jwt.sign(ECDSASigner(bindingKey))
            jwt.serialize()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to mint software key attestation: ${e.message}")
            null
        }
    }

    /**
     * Hardware tier ("android_keystore"): the KA is signed by the Android
     * Keystore binding key and carries the Google-rooted attestation chain in
     * x5c. The KeyDescription challenge in the leaf certificate must be the
     * c_nonce, so the key must be generated with that challenge.
     */
    fun mintHardwareKeyAttestation(
        signableKey: ECKey,
        x5cBase64: List<String>,
        cNonce: String?
    ): String? {
        return try {
            val now = Date()
            val header = JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType(KA_TYP))
                .x509CertChain(x5cBase64.map { com.nimbusds.jose.util.Base64(it) })
                .build()
            val claims = JWTClaimsSet.Builder()
                .issueTime(now)
                .expirationTime(Date(now.time + 12 * 60 * 60 * 1000))
                .claim("attested_keys", listOf(signableKey.toPublicJWK().toJSONObject()))
                .apply { if (!cNonce.isNullOrEmpty()) claim("nonce", cNonce) }
                .build()
            val jwt = SignedJWT(header, claims)
            jwt.sign(ECDSASigner(signableKey))
            jwt.serialize()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to mint hardware key attestation: ${e.message}")
            null
        }
    }

    /**
     * Proof of possession over the wallet-provider nonce, for the optional
     * wallet-provider endpoint. The key_pops array is positionally aligned
     * with attested_keys; the WIA cnf key's slot needs a placeholder.
     */
    fun generateKeyProofOfPossession(key: ECKey, nonce: String): String? {
        return try {
            val header = JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType(KEY_POP_TYP))
                .build()
            val claims = JWTClaimsSet.Builder()
                .issueTime(Date())
                .claim("nonce", nonce)
                .build()
            val jwt = SignedJWT(header, claims)
            jwt.sign(ECDSASigner(key))
            jwt.serialize()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create key proof of possession: ${e.message}")
            null
        }
    }

    /**
     * Single-use server nonce for the wallet-provider key-attestation
     * endpoint (GET .../wallet-provider/nonce). The Keystore key must be
     * generated with THIS nonce as the attestation challenge, and the
     * key PoPs must sign it.
     */
    suspend fun fetchKeyAttestationNonce(baseUrl: String): String? = withContext(Dispatchers.IO) {
        val result = SafeApiCall.safeApiCallResponse {
            ApiManager.api.getService()?.fetchNonce(url = "$baseUrl/wallet-provider/nonce")
        }
        result.onSuccess { response ->
            if (response.isSuccessful) {
                response.body()?.string()?.let {
                    return@withContext com.google.gson.Gson()
                        .fromJson(it, com.ewc.eudi_wallet_oidc_android.NonceResponse::class.java)
                        .nonce
                }
            } else {
                Log.e(TAG, "Failed to fetch key attestation nonce: ${response.errorBody()?.string()}")
            }
        }.onFailure { e ->
            Log.e(TAG, "Error fetching key attestation nonce: ${e.message}")
        }
        return@withContext null
    }

    /**
     * Optional: request a wallet-provider-signed KA. Only usable when the
     * credential issuer is the wallet-provider organisation (see class KDoc).
     * The wallet unit must be authorised on the wallet provider.
     */
    suspend fun requestKeyAttestation(
        baseUrl: String,
        walletUnitAttestationJWT: String,
        walletUnitProofOfPossession: String,
        nonce: String,
        attestedKeys: List<JWK>,
        keyPops: List<String>? = null,
        androidKeyAttestationX5c: List<String>? = null
    ): KeyAttestationResponse? = withContext(Dispatchers.IO) {
        val headers = WalletUnitAttestationHeaders.build(
            walletUnitAttestationJWT,
            walletUnitProofOfPossession
        ).apply {
            this["X-Wallet-Unit-Nonce"] = nonce
            this["X-Wallet-Unit-Platform"] = "android"
        }
        val body = KeyAttestationRequest(
            attestedKeys = attestedKeys.map { it.toPublicJWK().toJSONObject() },
            androidKeyAttestationX5c = androidKeyAttestationX5c,
            keyPops = keyPops
        )
        val result = SafeApiCall.safeApiCallResponse {
            ApiManager.api.getService()?.sendKeyAttestationRequest(
                url = "$baseUrl/wallet-provider/key-attestation",
                headers = headers,
                body = body
            )
        }
        result.onSuccess { response ->
            if (response.isSuccessful) {
                return@withContext response.body()
            } else {
                Log.e(TAG, "Key attestation request failed: ${response.errorBody()?.string()}")
                return@withContext null
            }
        }.onFailure { e ->
            Log.e(TAG, "Error sending key attestation request: ${e.message}")
            return@withContext null
        }
        return@withContext null
    }
}
