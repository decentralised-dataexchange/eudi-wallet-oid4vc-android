package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class InputDescriptors(

    @SerializedName("id") var id: String? = null,
    @SerializedName("constraints") var constraints: Constraints? = null

)

data class Constraints(

    @SerializedName("fields") var fields: ArrayList<Fields>? = null

)

data class Fields(

    @SerializedName("path") var path: ArrayList<String>? = null,
    @SerializedName("filter") var filter: Filter? = null

)

data class Filter(

    @SerializedName("type") var type: String? = null,
    @SerializedName("contains") var contains: Contains? = null,
    @SerializedName("pattern") var pattern: String? = null,
    @SerializedName("const") var const: String? = null

)

data class Contains(

    @SerializedName("const") var const: String? = null

)