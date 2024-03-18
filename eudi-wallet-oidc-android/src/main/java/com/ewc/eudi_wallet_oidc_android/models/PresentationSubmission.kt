package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class PresentationSubmission(

    @SerializedName("id") var id: String? = null,
    @SerializedName("definition_id") var definitionId: String? = null,
    @SerializedName("descriptor_map") var descriptorMap: ArrayList<DescriptorMap> = arrayListOf()

)

data class DescriptorMap(

    @SerializedName("id") var id: String? = null,
    @SerializedName("path") var path: String? = null,
    @SerializedName("format") var format: String? = null,
    @SerializedName("path_nested") var pathNested: PathNested? = PathNested()

)

data class PathNested(

    @SerializedName("id") var id: String? = null,
    @SerializedName("format") var format: String? = null,
    @SerializedName("path") var path: String? = null

)