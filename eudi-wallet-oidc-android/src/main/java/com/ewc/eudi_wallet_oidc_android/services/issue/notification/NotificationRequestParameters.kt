package com.ewc.eudi_wallet_oidc_android.services.issue.notification

import com.google.gson.annotations.SerializedName

/**
 * The notification request body, assembled once (section 11.1).
 *
 * Mirrors `NotificationRequestParameters` in the iOS SDK.
 */
internal data class NotificationRequestParameters(
    @SerializedName("notification_id") val notificationId: String,
    @SerializedName("event") val event: String,

    /**
     * Human-readable detail for the failure cases. Omitted rather than sent empty, as every other
     * leg omits its blanks.
     */
    @SerializedName("event_description") val eventDescription: String? = null,
) {
    companion object {
        fun build(
            notificationId: String,
            event: NotificationEvent,
            eventDescription: String? = null,
        ) = NotificationRequestParameters(
            notificationId = notificationId,
            event = event.value,
            eventDescription = eventDescription?.takeIf { it.isNotBlank() },
        )
    }
}
