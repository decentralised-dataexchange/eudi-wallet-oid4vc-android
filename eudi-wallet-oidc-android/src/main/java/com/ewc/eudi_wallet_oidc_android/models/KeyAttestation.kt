package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

/**
 * Request body of the wallet-provider key-attestation endpoint
 * (POST {baseUrl}/wallet-provider/key-attestation, ARF TS3 v1.5).
 */
data class KeyAttestationRequest(
    @SerializedName("attested_keys") var attestedKeys: List<Map<String, Any>>? = null,
    @SerializedName("android_key_attestation_x5c") var androidKeyAttestationX5c: List<String>? = null,
    @SerializedName("key_pops") var keyPops: List<String>? = null
)

data class KeyAttestationResponse(
    @SerializedName("keyAttestation") var keyAttestation: String? = null,
    @SerializedName("attestationType") var attestationType: String? = null,
    @SerializedName("keyStorage") var keyStorage: List<String>? = null
)
