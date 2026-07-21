package com.ewc.eudi_wallet_oidc_android.services.trust

import com.ewc.eudi_wallet_oidc_android.models.TrustServiceProvider

interface TrustMechanismInterface {
    suspend fun isIssuerOrVerifierTrusted(
        url: String? = null,
        x5c: String? = null,
        trustProvidersList: List<TrustServiceProvider>? = null,
        isDCQLVerificationFlow: Boolean = false
    ): Boolean

    suspend fun fetchTrustDetails(
        url: String? = null,
        x5c: String? = null,
        trustProvidersList: List<TrustServiceProvider>? = null
    ): TrustServiceProvider?
}
