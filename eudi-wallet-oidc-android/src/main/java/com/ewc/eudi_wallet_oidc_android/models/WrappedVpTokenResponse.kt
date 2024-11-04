package com.ewc.eudi_wallet_oidc_android.models
import com.google.gson.annotations.SerializedName
data class VPTokenResponse(
    @SerializedName("location") var location: String? = null,
    @SerializedName("redirect_uri") var redirectUri: String? = null
)

data class WrappedVpTokenResponse(
    var vpTokenResponse: VPTokenResponse? = null,
    var errorResponse: ErrorResponse? = null,
)