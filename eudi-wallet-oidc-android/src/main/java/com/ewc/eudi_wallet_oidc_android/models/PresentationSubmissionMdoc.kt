package com.ewc.eudi_wallet_oidc_android.models


import com.google.gson.annotations.SerializedName

data class PresentationSubmissionMdoc(

    @SerializedName("id") var id: String? = null,
    @SerializedName("definition_id") var definitionId: String? = null,
    @SerializedName("descriptor_map") var descriptorMap: ArrayList<DescriptorMapMdoc> = arrayListOf()

)

data class DescriptorMapMdoc(

    @SerializedName("id") var id: String? = null,
    @SerializedName("path") var path: String? = null,
    @SerializedName("format") var format: String? = null,

    )