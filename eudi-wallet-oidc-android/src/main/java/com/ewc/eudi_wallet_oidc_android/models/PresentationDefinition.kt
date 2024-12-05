package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class PresentationDefinition(

    @SerializedName("id") var id: String? = null,
    @SerializedName("name") var name: String? = null,
    @SerializedName("purpose") var purpose: String? = null,
    @SerializedName("format") var format: Map<String, Jwt>? = mapOf(),
    @SerializedName("input_descriptors") var inputDescriptors: ArrayList<InputDescriptors>? = arrayListOf()

)