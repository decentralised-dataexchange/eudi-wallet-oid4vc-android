package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class TokenResponse(

    @SerializedName("access_token") var accessToken: String? = null,
    @SerializedName("token_type") var tokenType: String? = null,
    @SerializedName("expires_in") var expiresIn: Int? = null,
    @SerializedName("id_token") var idToken: String? = null,
    @SerializedName("c_nonce") var cNonce: String? = null,
    @SerializedName("c_nonce_expires_in") var cNonceExpiresIn: Int? = null,
    @SerializedName("error") var error: String? = null,
    @SerializedName("error_description") var errorDescription: String? = null
)