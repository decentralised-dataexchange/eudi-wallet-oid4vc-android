package com.ewc.eudi_wallet_oidc_android.services.verification.request

import com.ewc.eudi_wallet_oidc_android.models.ErrorCodes

/**
 * Why a presentation request could not be resolved.
 *
 * Every failure carries a description meant for a user, because integrators show
 * `ErrorResponse.errorDescription` verbatim. [code] fills `ErrorResponse.error` when the SDK has a
 * code for the failure, and [oauthError] fills `ErrorResponse.errorCode` when OAuth 2.0 names one.
 */
sealed class PresentationRequestException(
    message: String,
    val code: Int? = null,
    val oauthError: String? = null,
    cause: Throwable? = null,
) : Exception(message, cause) {

    /** The scanned data carried none of the parameters that identify a presentation request. */
    class NoRequest : PresentationRequestException("This QR code does not contain a presentation request")

    /** Both `request` and `request_uri` present. RFC 9101 section 5 forbids this. */
    class AmbiguousRequest : PresentationRequestException(
        "The presentation request is invalid: it carries both request and request_uri",
        oauthError = INVALID_REQUEST,
    )

    /** The `request_uri` fetch failed; the detail is the verifier's error body when it sent one. */
    class FetchFailed(detail: String?) : PresentationRequestException(
        detail?.takeIf { it.isNotBlank() } ?: "Unable to process request"
    )

    /** The `request_uri` answered with an empty body. */
    class EmptyResponse : PresentationRequestException("Response is null or empty.")

    /** The request, or the request object inside it, could not be parsed. */
    class Malformed(detail: String = "Invalid Request") : PresentationRequestException(detail)

    /**
     * OpenID4VP 1.0 section 5.10.1: a request object fetched by POST does not echo the
     * `wallet_nonce` the wallet sent, or was encrypted to a key the wallet does not hold.
     */
    class NonceMismatch : PresentationRequestException("Request validation failed")

    /**
     * The request object carries no signature and the client identifier prefix is not
     * `redirect_uri`, the only prefix OpenID4VP 1.0 section 5.9 allows unsigned.
     */
    class UnsignedRequestObject : PresentationRequestException("Request validation failed")

    /**
     * OpenID4VP 1.0 section 5.10.1: "The Client Identifier value in the client_id Authorization
     * Request parameter and the Request Object client_id claim value MUST be identical, including
     * the Client Identifier Prefix." RFC 9101 section 5 says the same.
     */
    class ClientIdMismatch(val fromUri: String, val fromRequestObject: String) : PresentationRequestException(
        "The client_id in the request does not match the request object",
        oauthError = INVALID_REQUEST,
    )

    /** The `dcql_query` is not valid JSON or breaks OpenID4VP 1.0 section 6. */
    class InvalidDcqlQuery(reason: String?) : PresentationRequestException(
        "Invalid DCQL query: $reason",
        code = ErrorCodes.INVALID_DCQL_QUERY,
    )

    /** A draft `presentation_definition_uri` could not be fetched or did not parse. */
    class PresentationDefinitionUnavailable(detail: String?) : PresentationRequestException(
        "The presentation definition could not be fetched" +
            (detail?.takeIf { it.isNotBlank() }?.let { ": $it" } ?: "")
    )

    /**
     * The request broke the rules of its client identifier prefix (OpenID4VP 1.0 section 5.9.3),
     * so the verifier is not who the client_id says. Section 8.5 files this under invalid_request.
     */
    class ClientNotVerified(detail: String) : PresentationRequestException(
        "The verifier could not be authenticated: $detail",
        oauthError = INVALID_REQUEST,
    )

    /** Section 8.5: "The Wallet does not support the Client Identifier Prefix passed in the Authorization Request." */
    class UnsupportedClientIdPrefix(prefix: String) : PresentationRequestException(
        "The client identifier prefix '$prefix' is not supported",
        oauthError = INVALID_REQUEST,
    )

    /** Section 8.5 `invalid_transaction_data`. */
    class InvalidTransactionData(detail: String?) : PresentationRequestException(
        "The transaction data in the request is invalid: $detail",
        oauthError = "invalid_transaction_data",
    )

    /** A draft request arrived while [PresentationRequestPolicy.allowDraftRequests] is false. */
    class DraftNotAllowed : PresentationRequestException(
        "This presentation request uses a draft format that is not supported"
    )

    companion object {
        /** RFC 6749 section 4.1.2.1. */
        const val INVALID_REQUEST = "invalid_request"
    }
}
