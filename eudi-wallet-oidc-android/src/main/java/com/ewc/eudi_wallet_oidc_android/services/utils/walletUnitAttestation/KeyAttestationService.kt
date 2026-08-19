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
 * TS3 §2.2.2.1: the KA SHALL be generated and signed by the Wallet Provider —
 * the wallet never mints a KA itself. [requestKeyAttestation] sends the key
 * evidence (Android Keystore chain for the hardware tier, key PoPs for the
 * software tier) to the wallet-provider backend, which verifies it and signs
 * the KA. The nonce is the ISSUER's c_nonce for the credential request
 * (TS3 §2.2.2): the wallet passes it to the wallet provider, the evidence is
 * bound to it, and the issuer — not the wallet provider — validates its
 * freshness against its own nonce endpoint.
 */
object KeyAttestationService {
    const val TAG = "KeyAttestation"

    /** Shared watch tag for the KA path. Filter with: adb logcat -s KaWatch */
    private const val KA_WATCH = "KaWatch"

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
     * The KA that goes on a credential-request proof. Only a wallet-provider
     * issued KA is accepted (TS3 §2.2.2.1) — there is no on-device fallback.
     * Null when no KA is wanted, or when one was wanted but the wallet
     * provider did not deliver it (the issuer then rejects or warns).
     */
    fun forProof(
        walletProviderKa: String?,
        attach: Boolean
    ): String? {
        if (walletProviderKa != null) {
            Log.d(KA_WATCH, "proof KA source: wallet-provider issued")
            return walletProviderKa
        }
        if (attach) {
            Log.e(
                KA_WATCH,
                "KA wanted but the wallet provider did not deliver one — " +
                    "proof goes WITHOUT a KA (TS3: the wallet never self-mints)"
            )
        }
        return null
    }

    /**
     * Proof of possession over the issuer c_nonce, for the wallet-provider
     * key-attestation endpoint (software tier). The key_pops array is
     * positionally aligned with attested_keys; the WIA cnf key's slot needs
     * a placeholder.
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
     * Request the KA from the wallet provider (TS3 §2.2.2.1). The nonce is
     * the ISSUER's c_nonce for the credential request: the Keystore key must
     * be generated with it as the attestation challenge (hardware tier), or
     * the key PoPs must sign it (software tier). The wallet unit must be
     * registered and authorised on the wallet provider.
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
        Log.d(
            KA_WATCH,
            "POST $baseUrl/wallet-provider/key-attestation " +
                "keys=${attestedKeys.size} " +
                "evidence=${
                    if (androidKeyAttestationX5c != null)
                        "android_x5c(${androidKeyAttestationX5c.size} certs)"
                    else "key_pops(${keyPops?.size ?: 0})"
                } nonce=$nonce"
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
                val ka = response.body()
                Log.d(
                    KA_WATCH,
                    "WP KA response ${response.code()}: " +
                        "attestationType=${ka?.attestationType} keyStorage=${ka?.keyStorage}"
                )
                return@withContext ka
            } else {
                val error = response.errorBody()?.string()
                Log.e(TAG, "Key attestation request failed: $error")
                Log.e(KA_WATCH, "WP KA response ${response.code()}: $error")
                return@withContext null
            }
        }.onFailure { e ->
            Log.e(TAG, "Error sending key attestation request: ${e.message}")
            Log.e(KA_WATCH, "WP KA transport error: ${e.message}")
            return@withContext null
        }
        return@withContext null
    }
}
