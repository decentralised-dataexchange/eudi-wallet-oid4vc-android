package com.ewc.eudi_wallet_oidc_android.models

/**
 * Values of [ErrorResponse.error] that the SDK decides itself. HTTP status codes (100 to 599)
 * are passed through unchanged when a server answers with an error, so a new SDK code must
 * stay outside that range. Add every new code here, with its meaning, so there is one place
 * to look.
 */
object ErrorCodes {

    /** A server error body that could not be classified; the detail is in `errorDescription`. */
    const val UNCLASSIFIED = -1

    /** The proof JWT issuer did not match the client_id the issuer expected. */
    const val INVALID_DID = 1

    /**
     * The presentation request carries a `dcql_query` that breaks OpenID4VP 1.0, or one that is
     * not valid JSON. The description lists every violation. Produced by `DcqlQueryValidator`.
     */
    const val INVALID_DCQL_QUERY = 1001
}
