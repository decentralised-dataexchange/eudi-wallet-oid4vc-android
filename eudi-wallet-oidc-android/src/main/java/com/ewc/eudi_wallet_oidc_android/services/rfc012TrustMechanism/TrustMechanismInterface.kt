package com.ewc.eudi_wallet_oidc_android.services.rfc012TrustMechanism

import com.ewc.eudi_wallet_oidc_android.models.TrustServiceProvider

interface TrustMechanismInterface {
    suspend fun isIssuerOrVerifierTrusted(
        url: String? = null,
        x5c: String? = null
    ): Boolean

    suspend fun fetchTrustDetails(
        url: String? = null,
        x5c: String? = null
    ): TrustServiceProvider?
}
