package com.ewc.eudi_wallet_oidc_android.services.verification.response

/** Why a response could not be prepared or sent. The description is meant for a user. */
sealed class SubmissionException(message: String, val oauthError: String = "invalid_request", cause: Throwable? = null) :
    Exception(message, cause) {

    /** Section 8.2: `response_uri` is REQUIRED with direct_post; the draft `redirect_uri` is accepted in its place. */
    class NoResponseUri : SubmissionException("The request names no response_uri to send the presentation to")

    class UnsupportedResponseMode(raw: String) : SubmissionException("The response mode '$raw' is not supported")

    /** Section 8.3: no key in the client metadata the response could be encrypted to. */
    class NoEncryptionKey : SubmissionException("The verifier asked for an encrypted response but published no encryption key")

    /** Section 8.3: the verifier's key algorithm or content encryption is one this SDK does not support. */
    class EncryptionUnsupported(detail: String) : SubmissionException("The response cannot be encrypted: $detail")

    class EncryptionFailed(cause: Throwable?) : SubmissionException("The response could not be encrypted", cause = cause)
}
