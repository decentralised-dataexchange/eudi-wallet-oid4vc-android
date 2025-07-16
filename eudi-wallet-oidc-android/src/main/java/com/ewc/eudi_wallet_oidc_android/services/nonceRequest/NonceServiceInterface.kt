package com.ewc.eudi_wallet_oidc_android.services.nonceRequest


interface NonceServiceInterface {
    suspend fun fetchNonce(
        accessToken: String? = null,
        nonceEndPoint: String?
    ): String?

}