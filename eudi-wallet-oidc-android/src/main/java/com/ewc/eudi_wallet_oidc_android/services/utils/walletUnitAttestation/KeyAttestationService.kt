package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.KeyAttestationOutcome
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
import retrofit2.Response
import java.util.Date

/**
 * ARF TS3 v1.5 Key Attestation (KA).
 *
 * TS3 §2.2.2.1: the KA SHALL be generated and signed by the Wallet Provider —
 * the wallet never mints a KA itself. [requestKeyAttestation] and
 * [requestBatchKeyAttestation] send the key evidence (Android Keystore chain
 * per key for the hardware tier, key PoPs for the software tier) to the
 * wallet-provider backend, which verifies it and signs the KA. The nonce is
 * the ISSUER's c_nonce for the credential request (TS3 §2.2.2): the wallet
 * passes it to the wallet provider, the evidence is bound to it, and the
 * issuer — not the wallet provider — validates its freshness against its own
 * nonce endpoint.
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
     *
     * [androidKeyAttestationX5c] is ONE chain, for one attested key. For
     * several keys use [requestBatchKeyAttestation]. Non-2xx responses come
     * back as null, as before.
     */
    suspend fun requestKeyAttestation(
        baseUrl: String,
        walletUnitAttestationJWT: String,
        walletUnitProofOfPossession: String,
        nonce: String,
        attestedKeys: List<JWK>,
        keyPops: List<String>? = null,
        androidKeyAttestationX5c: List<String>? = null
    ): KeyAttestationResponse? = sendKeyAttestation(
        baseUrl = baseUrl,
        walletUnitAttestationJWT = walletUnitAttestationJWT,
        walletUnitProofOfPossession = walletUnitProofOfPossession,
        nonce = nonce,
        attestedKeys = attestedKeys,
        keyPops = keyPops,
        chains = androidKeyAttestationX5c?.let { listOf(it) },
        anyStatus = false
    ).response

    /**
     * Batch key attestation (#3347): one KA attesting every key in
     * [attestedKeys]. Hardware tier: [androidKeyAttestationX5cChains] carries
     * one Keystore chain per key, index-aligned (all keys must come from the
     * same keystore security level; every leaf carries [nonce] as its
     * attestation challenge). Software tier: [keyPops] carries one proof per
     * key. Keep the key count at or below the issuer's batch_size — a KA is
     * single use, so extra keys are wasted.
     *
     * The HTTP status is preserved: a 400 invalid_key_evidence (chain count
     * != key count) is reported in the outcome, not swallowed. No client-side
     * alignment check is done on purpose, so the wallet provider's own
     * validation can be exercised.
     */
    suspend fun requestBatchKeyAttestation(
        baseUrl: String,
        walletUnitAttestationJWT: String,
        walletUnitProofOfPossession: String,
        nonce: String,
        attestedKeys: List<JWK>,
        keyPops: List<String>? = null,
        androidKeyAttestationX5cChains: List<List<String>>? = null
    ): KeyAttestationOutcome = sendKeyAttestation(
        baseUrl = baseUrl,
        walletUnitAttestationJWT = walletUnitAttestationJWT,
        walletUnitProofOfPossession = walletUnitProofOfPossession,
        nonce = nonce,
        attestedKeys = attestedKeys,
        keyPops = keyPops,
        chains = androidKeyAttestationX5cChains,
        anyStatus = true
    )

    private suspend fun sendKeyAttestation(
        baseUrl: String,
        walletUnitAttestationJWT: String,
        walletUnitProofOfPossession: String,
        nonce: String,
        attestedKeys: List<JWK>,
        keyPops: List<String>?,
        chains: List<List<String>>?,
        anyStatus: Boolean
    ): KeyAttestationOutcome = withContext(Dispatchers.IO) {
        val headers = WalletUnitAttestationHeaders.build(
            walletUnitAttestationJWT,
            walletUnitProofOfPossession
        ).apply {
            this["X-Wallet-Unit-Nonce"] = nonce
            this["X-Wallet-Unit-Platform"] = "android"
        }
        val body = KeyAttestationRequest(
            attestedKeys = attestedKeys.map { it.toPublicJWK().toJSONObject() },
            androidKeyAttestationX5c = KeyAttestationRequest.x5cWire(chains),
            keyPops = keyPops
        )
        val evidence = when {
            chains != null && chains.size == 1 -> "android_x5c(${chains[0].size} certs)"
            chains != null -> "android_x5c_chains(${chains.size} chains, lens=${chains.map { it.size }})"
            else -> "key_pops(${keyPops?.size ?: 0})"
        }
        Log.d(
            KA_WATCH,
            "POST $baseUrl/wallet-provider/key-attestation " +
                "keys=${attestedKeys.size} evidence=$evidence nonce=$nonce"
        )
        val call: suspend () -> Response<KeyAttestationResponse>? = {
            ApiManager.api.getService()?.sendKeyAttestationRequest(
                url = "$baseUrl/wallet-provider/key-attestation",
                headers = headers,
                body = body
            )
        }
        val result = if (anyStatus) {
            SafeApiCall.safeApiCallAnyStatus(call)
        } else {
            SafeApiCall.safeApiCallResponse(call)
        }
        result.fold(
            onSuccess = { response ->
                if (response.isSuccessful) {
                    val ka = response.body()
                    Log.d(
                        KA_WATCH,
                        "WP KA response ${response.code()}: " +
                            "attestationType=${ka?.attestationType} keyStorage=${ka?.keyStorage} " +
                            "attestedKeysCount=${ka?.attestedKeysCount}"
                    )
                    KeyAttestationOutcome(response.code(), ka, null)
                } else {
                    val error = try {
                        response.errorBody()?.string()
                    } catch (e: Exception) {
                        null
                    }
                    Log.e(TAG, "Key attestation request failed: $error")
                    Log.e(KA_WATCH, "WP KA response ${response.code()}: $error")
                    KeyAttestationOutcome(response.code(), null, error)
                }
            },
            onFailure = { e ->
                Log.e(TAG, "Error sending key attestation request: ${e.message}")
                Log.e(KA_WATCH, "WP KA transport error: ${e.message}")
                KeyAttestationOutcome(null, null, e.message)
            }
        )
    }
}
