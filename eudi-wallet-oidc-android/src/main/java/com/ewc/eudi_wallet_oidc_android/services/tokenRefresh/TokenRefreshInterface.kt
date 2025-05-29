package com.ewc.eudi_wallet_oidc_android.services.tokenRefresh

import com.ewc.eudi_wallet_oidc_android.models.WrappedRefreshTokenResponse

interface TokenRefreshInterface {

    suspend fun refreshToken(
        tokenEndPoint: String?,
        refreshToken: String?,
    ): WrappedRefreshTokenResponse?
}