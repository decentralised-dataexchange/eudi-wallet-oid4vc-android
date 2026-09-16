package com.ewc.eudi_wallet_oidc_android

import com.google.gson.annotations.SerializedName

/** Body of GET {service}/nonce and GET {service}/wallet-provider/nonce. */
data class NonceResponse(
    @SerializedName("nonce") var nonce: String? = null,
    /** Also returned by the wallet provider; the challenge for key attestation. */
    @SerializedName("c_nonce") var cNonce: String? = null
)
