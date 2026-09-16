package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

/**
 * Request body of the wallet-provider key-attestation endpoint
 * (POST {baseUrl}/wallet-provider/key-attestation, ARF TS3 v1.5).
 */
data class KeyAttestationRequest(
    @SerializedName("attested_keys") var attestedKeys: List<Map<String, Any>>? = null,
    /**
     * Android Keystore evidence. Two wire shapes share this name (#3347):
     *  - flat `List<String>`: ONE chain (leaf first) for a single attested key;
     *  - nested `List<List<String>>`: one chain per key, index-aligned with
     *    [attestedKeys] (batch key attestation).
     * Gson serialises by the runtime element type, so one field carries both.
     * Build the value with [x5cWire].
     */
    @SerializedName("android_key_attestation_x5c") var androidKeyAttestationX5c: List<Any>? = null,
    @SerializedName("key_pops") var keyPops: List<String>? = null
) {
    companion object {
        /**
         * Flat form for exactly one chain (the shape the wallet provider has
         * always accepted), nested form for two or more.
         */
        fun x5cWire(chains: List<List<String>>?): List<Any>? = when {
            chains == null -> null
            chains.size == 1 -> chains[0]
            else -> chains
        }
    }
}

data class KeyAttestationResponse(
    @SerializedName("keyAttestation") var keyAttestation: String? = null,
    @SerializedName("attestationType") var attestationType: String? = null,
    @SerializedName("keyStorage") var keyStorage: List<String>? = null,
    /** Number of keys the returned KA attests (batch key attestation, #3347). */
    @SerializedName("attestedKeysCount") var attestedKeysCount: Int? = null
)

/**
 * Outcome of a key-attestation request that keeps the HTTP status: a 4xx from
 * the wallet provider (for example 400 invalid_key_evidence) is a result the
 * caller can inspect, not a transport failure.
 */
data class KeyAttestationOutcome(
    /** Null when the request never reached the server (transport error). */
    val httpCode: Int?,
    val response: KeyAttestationResponse?,
    val errorBody: String?
) {
    val isSuccessful: Boolean
        get() = httpCode != null && httpCode in 200..299 && response?.keyAttestation != null
}
