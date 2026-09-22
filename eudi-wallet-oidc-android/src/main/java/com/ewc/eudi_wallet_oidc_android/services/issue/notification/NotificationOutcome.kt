package com.ewc.eudi_wallet_oidc_android.services.issue.notification

import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse

/**
 * What the notification request produced.
 *
 * Replaces `Unit`. The previous implementation logged the outcome and returned nothing, so a caller
 * could not tell an acknowledged notification from one the issuer rejected -- and section 11.2's
 * 204 from a 400 naming `invalid_notification_id`.
 */
sealed class NotificationOutcome {

    /** Section 11.2: the issuer accepted it. No body is returned. */
    data object Acknowledged : NotificationOutcome()

    /** The issuer refused it, with its own error code where it sent one. */
    data class Failed(val error: ErrorResponse) : NotificationOutcome()
}
