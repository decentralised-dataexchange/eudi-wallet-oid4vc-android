package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class PresentationDefinition(

    @SerializedName("id") var id: String? = null,
    @SerializedName("format") var format: VpFormatsSupported? = VpFormatsSupported(),
    @SerializedName("input_descriptors") var inputDescriptors: ArrayList<InputDescriptors>? = arrayListOf()

)