package com.ewc.eudi_wallet_oidc_android

import com.google.gson.annotations.SerializedName

data class NonceResponse(
    @SerializedName("nonce") var nonce: String? = null
)