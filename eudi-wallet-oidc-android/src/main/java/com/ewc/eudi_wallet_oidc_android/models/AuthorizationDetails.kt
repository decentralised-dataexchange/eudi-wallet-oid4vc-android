package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class AuthorizationDetails(

    @SerializedName("type") var type: String? = "openid_credential",
    @SerializedName("format") var format: String? = "jwt_vc",
    @SerializedName("types") var types: ArrayList<String>? = arrayListOf(),
    @SerializedName("locations") var locations: ArrayList<String>? = arrayListOf()

)