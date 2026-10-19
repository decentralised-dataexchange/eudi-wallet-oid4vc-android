package com.ewc.eudi_wallet_oidc_android.services.notification

import com.ewc.eudi_wallet_oidc_android.services.issue.notification.NotificationEvent

/**
 * Moved to `services/issue/notification/NotificationEvent`, so both SDKs name it the same thing and
 * keep it with the leg that sends it.
 *
 * Kept here as an alias because `data-wallet-android` imports this package path.
 */
@Deprecated(
    "Renamed to NotificationEvent and moved to services.issue.notification.",
    ReplaceWith("NotificationEvent", "com.ewc.eudi_wallet_oidc_android.services.issue.notification.NotificationEvent"),
)
typealias NotificationEventType = NotificationEvent
