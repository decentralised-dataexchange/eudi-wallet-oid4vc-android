package com.ewc.eudi_wallet_oidc_android.models

/**
 * Values of [ErrorResponse.error] that the SDK decides itself. HTTP status codes (100 to 599)
 * are passed through unchanged when a server answers with an error, so a new SDK code must
 * stay outside that range. Add every new code here, with its meaning, so there is one place
 * to look. Mirrors `ErrorCodes` in the iOS SDK.
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

    /**
     * A wallet provider protocol 2 request could not be made on this device: no nonce, a key
     * that cannot be bound, the device key or Play Integrity refused. Nothing was sent, or the
     * wallet provider gave no usable answer.
     */
    const val WALLET_PROVIDER_REQUEST_FAILED = 1101

    /** The wallet provider could not be reached (no network, a timeout). Show nothing; try again later. */
    const val WALLET_PROVIDER_UNREACHABLE = 1102

    /**
     * The device key of the wallet unit is gone from this device (a restored backup, a new
     * phone). The app must start a new wallet unit.
     */
    const val WALLET_UNIT_KEY_LOST = 1103
}
