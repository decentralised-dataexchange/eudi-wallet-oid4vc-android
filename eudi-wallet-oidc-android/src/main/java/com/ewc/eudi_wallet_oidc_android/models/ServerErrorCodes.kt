package com.ewc.eudi_wallet_oidc_android.models

/**
 * Values of [ErrorResponse.errorCode]: the `error` string a server sent, as defined by RFC 6749,
 * OpenID4VCI and OpenID4VP. Compare against these instead of typing the strings.
 *
 * Not to be confused with [ErrorCodes], whose integers are decided by the SDK itself. Errors that
 * arrive as an RFC 9457 problem carry no code at all; for those read [ErrorResponse.httpStatus].
 */
object ServerErrorCodes {
    // RFC 6749 / RFC 6750
    const val INVALID_REQUEST = "invalid_request"
    const val INVALID_CLIENT = "invalid_client"
    const val INVALID_GRANT = "invalid_grant"
    const val UNAUTHORIZED_CLIENT = "unauthorized_client"
    const val ACCESS_DENIED = "access_denied"
    const val INVALID_TOKEN = "invalid_token"
    const val SERVER_ERROR = "server_error"
    const val TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"

    // OpenID4VCI
    const val INVALID_CREDENTIAL_REQUEST = "invalid_credential_request"
    const val UNKNOWN_CREDENTIAL_CONFIGURATION = "unknown_credential_configuration"
    const val UNKNOWN_CREDENTIAL_IDENTIFIER = "unknown_credential_identifier"
    const val INVALID_PROOF = "invalid_proof"
    const val INVALID_NONCE = "invalid_nonce"
    const val CREDENTIAL_REQUEST_DENIED = "credential_request_denied"
    const val INVALID_TRANSACTION_ID = "invalid_transaction_id"
    const val ISSUANCE_PENDING = "issuance_pending"

    // OpenID4VP
    const val VP_FORMATS_NOT_SUPPORTED = "vp_formats_not_supported"
    const val INVALID_TRANSACTION_DATA = "invalid_transaction_data"
    const val WALLET_UNAVAILABLE = "wallet_unavailable"
}
