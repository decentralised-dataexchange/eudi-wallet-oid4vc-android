package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.JsonObject
import com.google.gson.annotations.SerializedName

data class CredentialRequestEncryptionInfo(
    @SerializedName("encryption_required") var encryptionRequired: Boolean? = null,
    @SerializedName("jwk") var jwk: JsonObject? = null
)
