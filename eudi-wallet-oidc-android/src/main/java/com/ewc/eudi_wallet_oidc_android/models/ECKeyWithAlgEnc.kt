package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName
import com.nimbusds.jose.jwk.ECKey

data class ECKeyWithAlgEnc(
    @SerializedName("ecKey") var ecKey: ECKey? = null,
    @SerializedName("alg") var alg: String? = null,
    @SerializedName("enc") var enc: String? = null,
)