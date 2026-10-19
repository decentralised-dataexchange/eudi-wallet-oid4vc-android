package com.ewc.eudi_wallet_oidc_android.services.issue.deferred

/**
 * The handle the issuer gave out when it deferred a credential.
 *
 * OpenID4VCI 1.0 section 9.1 names it `transaction_id` and makes it REQUIRED. The pre-1.0 drafts
 * called it `acceptance_token` and sent it as a **bearer token in the Authorization header** with an
 * empty body -- not as a body parameter at all. Those are two different requests, which is why there
 * were two whole functions and a stored `version` integer choosing between them.
 *
 * A sealed type puts that choice where it belongs: on the value itself. The caller holds a handle,
 * not a handle plus a version flag that has to agree with it.
 *
 * Mirrors `DeferredTransaction` in the iOS SDK.
 */
sealed class DeferredTransaction {

    /** The handle, whichever revision issued it. */
    abstract val value: String

    /**
     * Section 9.1: `transaction_id` in the request body, with the access token in the header.
     *
     * @param credentialIdentifier section 9.1 says this MAY be included; send it when the credential
     *   was requested by identifier, so the issuer knows which of several it is being asked about.
     */
    data class TransactionId(
        override val value: String,
        val credentialIdentifier: String? = null,
    ) : DeferredTransaction()

    /**
     * The pre-1.0 draft form: the handle *is* the bearer token and the body is empty.
     *
     * The single case to delete when draft support goes, as `CredentialSubject.LegacyFormat` is.
     */
    data class LegacyAcceptanceToken(override val value: String) : DeferredTransaction()
}
