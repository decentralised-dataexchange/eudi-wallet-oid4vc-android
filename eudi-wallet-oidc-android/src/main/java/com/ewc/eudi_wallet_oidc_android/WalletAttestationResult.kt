package com.ewc.eudi_wallet_oidc_android


import com.google.gson.annotations.SerializedName
import com.nimbusds.jose.jwk.ECKey

data class WalletAttestationResult(
    @SerializedName("credentialOffer") var credentialOffer: String? = null,
    @SerializedName("walletUnitAttestation") var walletUnitAttestation: String? = null,
    @SerializedName("clientAssertion") var clientAssertion: String? = null,
    @SerializedName("did") var did: String? = null,
    @SerializedName("ecKey") var ecKey:  ECKey? = null,
    @SerializedName("credentialIssuer") var credentialIssuer: String? = null,
)
