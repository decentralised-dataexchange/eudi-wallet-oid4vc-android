package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName


data class CredentialRequest(

    @SerializedName("types") var types: ArrayList<String>? = null,
    @SerializedName("credential_definition") var credentialDefinition: CredentialDefinition? = null,
    @SerializedName("vct") var vct: String? = null,
    @SerializedName("format") var format: String? = null,
    @SerializedName("doctype") var doctype: String? = null,
    @SerializedName("proof") var proof: ProofV3? = null,
    @SerializedName("credential_identifier") var credentialIdentifier: String? = null,
    @SerializedName("credential_configuration_id") var credentialConfigurationId: String? = null,
)

data class CredentialDefinition(
    @SerializedName("vct") var vct: String? = null,
    @SerializedName("type") var type: ArrayList<String>? = null
)
data class ProofV3(

    @SerializedName("proof_type") var proofType: String? = null,
    @SerializedName("jwt") var jwt: String? = null

)