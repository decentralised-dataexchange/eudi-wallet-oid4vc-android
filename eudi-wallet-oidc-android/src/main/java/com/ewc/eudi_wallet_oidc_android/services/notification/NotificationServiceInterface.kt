package com.ewc.eudi_wallet_oidc_android.services.notification

import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletAttestation
import com.ewc.eudi_wallet_oidc_android.services.issue.notification.NotificationEvent
import com.ewc.eudi_wallet_oidc_android.services.issue.notification.NotificationOutcome

import com.ewc.eudi_wallet_oidc_android.models.WrappedRefreshTokenResponse

interface NotificationServiceInterface {

    /** @see NotificationService.notify */
    suspend fun notify(
        session: IssuanceSession,
        token: TokenResponse,
        notificationId: String,
        event: NotificationEvent,
        eventDescription: String? = null,
        attestation: WalletAttestation? = null,
        dpopNonce: String? = null,
    ): NotificationOutcome

    @Deprecated(
        "Returns Unit, so success and refusal are indistinguishable. Use notify, which returns a NotificationOutcome.",
        ReplaceWith("notify(session, token, notificationId, event)"),
    )
    suspend fun sendNotificationRequest(
        notificationEndPoint: String?,
        accessToken: String?,
        notificationId: String?,
        event: NotificationEvent
    )
}