package com.ewc.eudi_wallet_oidc_android.services.tokenRefresh

import com.ewc.eudi_wallet_oidc_android.models.WrappedRefreshTokenResponse
import com.nimbusds.jose.jwk.ECKey

interface TokenRefreshInterface {

    suspend fun refreshToken(
        tokenEndPoint: String?,
        refreshToken: String?,
        walletUnitAttestationJWT: String? = null,
        walletUnitProofOfPossession: (() -> String?)? = null,
        dpopKey: ECKey? = null,
    ): WrappedRefreshTokenResponse?
}