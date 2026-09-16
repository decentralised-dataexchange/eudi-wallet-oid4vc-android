package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

/**
 * Body of POST {baseUrl}/wallet-unit/request/batch (#3347): one client
 * assertion per wallet instance attestation wanted. Each assertion is signed
 * by its own key and carries that key in cnf.jwk; all share one client_id.
 */
data class BatchClientAssertion(
    @SerializedName("client_assertions") var clientAssertions: List<String>? = null,
    @SerializedName("client_assertion_type") var clientAssertionType: String? = null,
    @SerializedName("profile") var profile: String? = null
)
