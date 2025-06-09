package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class NonceResponse(
    @SerializedName("c_nonce")
    var cNonce: String? = null,

    @SerializedName("c_nonce_expires_in")
    var cNonceExpiresIn: Int? = null
)