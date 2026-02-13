package com.ewc.eudi_wallet_oidc_android

import com.google.gson.annotations.SerializedName

data class CredentialOfferResponse(
    @SerializedName("credentialOffer") var credentialOffer: String? = null,
    @SerializedName("walletUnitAttestation") var walletUnitAttestation: String? = null,
    @SerializedName("credentialIssuer") var credentialIssuer: String? = null,
)