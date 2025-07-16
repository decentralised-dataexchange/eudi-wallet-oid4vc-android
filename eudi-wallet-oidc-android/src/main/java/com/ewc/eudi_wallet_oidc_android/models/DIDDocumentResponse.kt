package com.ewc.eudi_wallet_oidc_android.models

import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.PublicKeyJwk
import com.google.gson.annotations.SerializedName

data class DataResponse(
    @SerializedName("value") val value: Value ? =null,
)

data class Value(
    @SerializedName("@context") val context: List<String>?=null,

    @SerializedName("id") val id: String?=null,

    @SerializedName("authentication") val authentication: List<String>?=null,

    @SerializedName("assertionMethod") val assertionMethod: List<String>?=null,

    @SerializedName("verificationMethod") val verificationMethod: List<VerificationMethods>?=null
)

data class VerificationMethods(
    @SerializedName("id") val id: String?=null,

    @SerializedName("controller") val controller: String?=null,

    @SerializedName("type") val type: String?=null,

    @SerializedName("publicKeyJwk") val publicKeyJwk: PublicKeyJwk?=null
)

