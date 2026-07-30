package com.ewc.eudi_wallet_oidc_android.services.trust

import com.ewc.eudi_wallet_oidc_android.models.TrustServiceProvider

interface TrustMechanismInterface {
    /**
     * @param x5cChain the full certificate chain from the request, **leaf first** (as in a JWS `x5c`
     * header or a COSE `x5chain`). Supply this whenever the request carries more than the signing
     * certificate: a trust list may register the CA or an intermediate rather than the leaf, and only
     * a lookup that sees the whole chain can match such an entry. When null (or empty) the lookup
     * falls back to the single [x5c] identifier.
     */
    suspend fun isIssuerOrVerifierTrusted(
        url: String? = null,
        x5c: String? = null,
        trustProvidersList: List<TrustServiceProvider>? = null,
        isDCQLVerificationFlow: Boolean = false,
        x5cChain: List<String>? = null
    ): Boolean

    /** @param x5cChain see [isIssuerOrVerifierTrusted]; full chain, leaf first. */
    suspend fun fetchTrustDetails(
        url: String? = null,
        x5c: String? = null,
        trustProvidersList: List<TrustServiceProvider>? = null,
        x5cChain: List<String>? = null
    ): TrustServiceProvider?
}
