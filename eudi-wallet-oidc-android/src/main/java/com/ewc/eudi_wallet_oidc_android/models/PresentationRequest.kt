package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class PresentationRequest(
    @SerializedName("state") var state: String? = null,
    @SerializedName("client_id") var clientId: String? = null,
    @SerializedName("redirect_uri") var redirectUri: String? = null,
    @SerializedName("response_type") var responseType: String? = null,
    @SerializedName("response_mode") var responseMode: String? = null,
    @SerializedName("scope") var scope: String? = null,
    @SerializedName("nonce") var nonce: String? = null,
    @SerializedName("request_uri") var requestUri: String? = null,
    @SerializedName("presentation_definition") var presentationDefinition: Any? = null
)
