package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class ClientMetaData(

    @SerializedName("vp_formats_supported") var vpFormatsSupported: VpFormatsSupported? = VpFormatsSupported(
        jwtVp = Jwt(arrayListOf("ES256")), jwtVc = Jwt(arrayListOf("ES256"))
    ),
    @SerializedName("response_types_supported") var responseTypesSupported: ArrayList<String> = arrayListOf(
        "vp_token",
        "id_token"
    ),
    @SerializedName("authorization_endpoint") var authorizationEndpoint: String? = null

)