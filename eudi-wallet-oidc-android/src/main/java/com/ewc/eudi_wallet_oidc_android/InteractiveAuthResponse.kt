package com.ewc.eudi_wallet_oidc_android

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.google.gson.annotations.SerializedName

data class InteractiveAuthResponse(
    @SerializedName("status") val status: String? = null,
    @SerializedName("type") val type: String? = null,
    @SerializedName("auth_session") val authSession: String? = null,
    @SerializedName("openid4vp_request") val openid4vpRequest: PresentationRequest? = null,
    @SerializedName("request_uri") val requestUri: String? = null,
    @SerializedName("expires_in") val expiresIn: Int? = null
)

