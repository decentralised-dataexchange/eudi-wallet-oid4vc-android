package com.ewc.eudi_wallet_oidc_android

import com.google.gson.annotations.SerializedName

/**
 * Response of POST {baseUrl}/wallet-unit/request/batch (#3347).
 * [walletUnitAttestations] is index-aligned with the request's client_assertions.
 */
data class BatchCredentialOfferResponse(
    @SerializedName("walletUnitAttestations") var walletUnitAttestations: List<String>? = null,
    @SerializedName("credentialIssuer") var credentialIssuer: String? = null,
    @SerializedName("credentialOffer") var credentialOffer: String? = null,
)
