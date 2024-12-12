package com.ewc.eudi_wallet_oidc_android


import com.google.gson.annotations.SerializedName

data class WalletAttestationResult(
    @SerializedName("credentialOffer") var credentialOffer: String? = null,
    @SerializedName("clientAssertion") var clientAssertion: String? = null
)
