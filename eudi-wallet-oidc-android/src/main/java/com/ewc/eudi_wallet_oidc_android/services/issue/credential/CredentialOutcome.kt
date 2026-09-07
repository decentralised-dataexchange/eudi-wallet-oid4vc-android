package com.ewc.eudi_wallet_oidc_android.services.issue.credential

import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse

/**
 * What the credential request produced.
 *
 * Replaces a `CredentialResponse` that carried the wire fields *and* five wallet-side scratch
 * fields, three of which (`isDeferred`, `isPinRequired`, `authorizationConfig`) had **no references
 * anywhere** -- so "is this deferred?" was answered by callers testing whether an
 * `acceptance_token` happened to be non-null.
 */
sealed class CredentialOutcome {

    /**
     * The issuer returned credentials.
     *
     * @param credentials **every** credential the response carried. Section 8.3's `credentials` is
     *   an array; the previous implementation read index 0 and silently dropped the rest, at six
     *   call sites in the wallet. Draft issuers returning a single `credential` arrive here as a
     *   one-element list.
     * @param notificationId section 11: the handle for telling the issuer the credential was
     *   accepted or refused.
     * @param cNonce a fresh nonce for the next request, which section 8.3 says the issuer SHOULD
     *   return.
     */
    data class Issued(
        val credentials: List<String>,
        val notificationId: String? = null,
        val cNonce: String? = null,
    ) : CredentialOutcome()

    /**
     * The credential is not ready; section 9's Deferred Credential Endpoint has it.
     *
     * Named here from the outset even though the deferred *request* is the next pass -- recognising
     * a deferred response and acting on it are separate things, and this is the recognising half.
     *
     * @param transactionId 1.0's handle. Draft issuers send `acceptance_token` instead; both land
     *   here.
     * @param interval seconds to wait before asking again, when the issuer said.
     */
    data class Deferred(
        val transactionId: String,
        val interval: Int? = null,
    ) : CredentialOutcome()

    /** The request failed, with the issuer's own error code where it sent one. */
    data class Failed(val error: ErrorResponse) : CredentialOutcome()
}
