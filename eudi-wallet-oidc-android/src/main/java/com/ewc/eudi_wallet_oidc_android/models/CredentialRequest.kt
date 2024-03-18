package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName


data class CredentialRequest(

    @SerializedName("types") var types: ArrayList<String>? = null,
    @SerializedName("format") var format: String? = null,
    @SerializedName("proof") var proof: ProofV3? = null

)

data class ProofV3(

    @SerializedName("proof_type") var proofType: String? = null,
    @SerializedName("jwt") var jwt: String? = null

)