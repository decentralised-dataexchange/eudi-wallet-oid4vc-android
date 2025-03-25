package com.ewc.eudi_wallet_oidc_android.services.notification

import com.ewc.eudi_wallet_oidc_android.models.WrappedRefreshTokenResponse

interface NotificationServiceInterface {
    suspend fun processRefreshTokenRequest(
        tokenEndPoint: String?,
        refreshToken: String?,
    ): WrappedRefreshTokenResponse?
    suspend fun sendNotificationRequest(
        notificationEndPoint: String?,
        accessToken: String?,
        notificationId: String?,
        event: String?
    )
}