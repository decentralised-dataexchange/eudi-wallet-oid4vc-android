package com.ewc.eudi_wallet_oidc_android.services.tokenRefresh

import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedRefreshTokenResponse
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager

class TokenRefreshService : TokenRefreshInterface {

    /**
    Attempts to refresh an access token using a refresh token.

    @param tokenEndPoint The OAuth 2.0 token endpoint URL where the refresh request will be sent
    @param refreshToken The refresh token to be used for obtaining a new access token
    @return WrappedRefreshTokenResponse? which contains either:
    - A successful token response with new access token and related data
    - An error response if the refresh operation fails
    - null if the operation cannot be completed
     */
    override suspend fun refreshToken(
        tokenEndPoint: String?,
        refreshToken: String?
    ): WrappedRefreshTokenResponse? {
        val response = ApiManager.api.getService()?.getRefreshTokenFromCode(
            tokenEndPoint ?: "",
            if (refreshToken !=null){
                println("refreshToken is not null and generating new accessToken")
                mutableMapOf(
                    "grant_type" to "refresh_token",
                    "refresh_token" to (refreshToken),
                )
            }
            else {
                mutableMapOf(
                    "grant_type" to null,
                    "refresh_token" to (null),
                )
            },
        )

        val tokenResponse = when {
            response?.isSuccessful == true -> {
                WrappedRefreshTokenResponse(
                    tokenResponse = response.body()
                )
            }

            (response?.code() ?: 0) >= 400 -> {
                try {
                    WrappedRefreshTokenResponse(
                        errorResponse = ErrorResponse(error = null, errorDescription = response?.errorBody().toString())
                    )
                } catch (e: Exception) {
                    null
                }
            }

            else -> {
                null
            }
        }
        return tokenResponse
    }
}