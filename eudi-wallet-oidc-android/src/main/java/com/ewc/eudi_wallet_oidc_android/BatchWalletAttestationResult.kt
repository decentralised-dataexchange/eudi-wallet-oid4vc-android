package com.ewc.eudi_wallet_oidc_android

import com.nimbusds.jose.jwk.ECKey

/**
 * One wallet instance attestation of a batch together with the key it is
 * bound to. Holds a private key: never serialise or log it.
 */
data class BatchWalletUnit(
    val index: Int,
    /** did:key of THIS unit's cnf key. */
    val did: String?,
    /** The cnf key, private part included. */
    val ecKey: ECKey,
    val clientAssertion: String,
    /** walletUnitAttestations[index]; null when the provider returned fewer. */
    val walletUnitAttestation: String?
)

/** Result of [WalletUnitAttestationService.initiateBatchWalletUnitAttestation]. */
data class BatchWalletAttestationResult(
    /** The client_id shared by every assertion of the batch. */
    val clientId: String,
    /** Play Integrity request hash that was sent, for diagnostics. */
    val requestHash: String?,
    /** Null when the request never reached the server. */
    val httpCode: Int?,
    val errorBody: String?,
    val credentialOffer: String?,
    val credentialIssuer: String?,
    /** Same size and order as the keys generated for the request. */
    val units: List<BatchWalletUnit>
) {
    val attestations: List<String>
        get() = units.mapNotNull { it.walletUnitAttestation }

    /**
     * Unit 0 in the single-attestation shape the app already stores. Null when
     * the provider did not return an attestation at index 0.
     */
    fun toSingleResult(): WalletAttestationResult? {
        val unit = units.firstOrNull() ?: return null
        val attestation = unit.walletUnitAttestation ?: return null
        return WalletAttestationResult(
            credentialOffer = credentialOffer,
            walletUnitAttestation = attestation,
            clientAssertion = unit.clientAssertion,
            did = unit.did,
            ecKey = unit.ecKey,
            credentialIssuer = credentialIssuer
        )
    }
}
