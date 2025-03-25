package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class RefreshTokenResponse(

    @SerializedName("access_token") var accessToken: String? = null,
    @SerializedName("refresh_token") var refreshToken: String? = null,
)

data class WrappedRefreshTokenResponse(
    var tokenResponse: RefreshTokenResponse? = null,
    var errorResponse: ErrorResponse? = null,
)