package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class ClientAssertion(
    @SerializedName("client_assertion") var clientAssertion: String? = null,
    @SerializedName("client_assertion_type") var clientAssertionType: String? = null,
    // ARF TS3 v1.5 opt-in: "ts3" requests a TS3-shaped WIA (x5c identity,
    // client_status). Null keeps the legacy EWC shape and is omitted on the wire.
    @SerializedName("profile") var profile: String? = null
)