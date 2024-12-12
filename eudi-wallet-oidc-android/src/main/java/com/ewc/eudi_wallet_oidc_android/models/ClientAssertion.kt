package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class ClientAssertion(
    @SerializedName("client_assertion") var clientAssertion: String? = null,
    @SerializedName("client_assertion_type") var clientAssertionType: String? = null
)