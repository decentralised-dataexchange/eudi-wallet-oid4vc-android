package com.ewc.eudi_wallet_oidc_android.services.notification

import com.ewc.eudi_wallet_oidc_android.models.WrappedRefreshTokenResponse
import com.nimbusds.jose.jwk.ECKey

interface NotificationServiceInterface {

    suspend fun sendNotificationRequest(
        notificationEndPoint: String?,
        accessToken: String?,
        notificationId: String?,
        event: NotificationEventType,
        dpopKey: ECKey? = null
    )
}