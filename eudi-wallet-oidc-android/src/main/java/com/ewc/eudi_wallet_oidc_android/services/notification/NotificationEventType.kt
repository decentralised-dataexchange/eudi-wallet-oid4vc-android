package com.ewc.eudi_wallet_oidc_android.services.notification

/**
 * Represents the type of notification events for credential operations as defined in EWC-RFC001.
 *
 * These events are used by the Wallet to notify the Issuer about the status of credential operations
 * through the notification endpoint. The events indicate whether a credential was successfully stored,
 * deleted by user action, or failed to be stored due to technical issues.
 *
 * Reference: EWC-RFC001 Section 6.1.4 Notification Request
 *
 * @property value The string representation of the notification event type used in API requests.
 */
enum class NotificationEventType(val value: String) {
    /** Indicates that the credential was successfully stored in the wallet. */
    CREDENTIAL_ACCEPTED("credential_accepted"),
    /** Indicates that the credential was not stored due to user-initiated deletion or rejection. */
    CREDENTIAL_DELETED("credential_deleted"),
    /** Indicates that the credential storage failed due to technical issues, not user action. */
    CREDENTIAL_FAILURE("credential_failure");

    companion object {
        /**
         * Converts a string value to its corresponding [NotificationEventType].
         *
         * @param value The string value to convert, matching the API event types.
         * @return The matching [NotificationEventType], or null if no match is found.
         */
        fun fromString(value: String): NotificationEventType? =
            values().find { it.value == value }
    }
}