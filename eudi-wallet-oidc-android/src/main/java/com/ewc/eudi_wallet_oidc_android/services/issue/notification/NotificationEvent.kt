package com.ewc.eudi_wallet_oidc_android.services.issue.notification

/**
 * What the wallet is telling the issuer happened to a credential (section 11.1).
 *
 * Named identically on both platforms. iOS called this `NotificationStatus` and **declared only two
 * of the three values** -- it had no way to report a storage failure at all, which is the case the
 * issuer most needs to hear about.
 */
enum class NotificationEvent(val value: String) {

    /** Stored successfully. */
    CREDENTIAL_ACCEPTED("credential_accepted"),

    /** Not stored, by the user's choice -- declined or deleted. */
    CREDENTIAL_DELETED("credential_deleted"),

    /** Not stored for a technical reason, not a user decision. */
    CREDENTIAL_FAILURE("credential_failure");

    companion object {
        fun fromString(value: String): NotificationEvent? = entries.find { it.value == value }
    }
}
