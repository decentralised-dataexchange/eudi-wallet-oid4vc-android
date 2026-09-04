package com.ewc.eudi_wallet_oidc_android.services.issue.authorization

import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.services.utils.ErrorHandler

/**
 * Why an authorization request could not be completed.
 *
 * Internal to the package: the resolver turns these into an [AuthorizationResponse] whose outcome
 * is [AuthorizationOutcome.FAILED], so a caller never has to catch anything.
 */
internal sealed class AuthorizationException(
    message: String,
    val errorCode: String? = null,
    val httpStatus: Int? = null,
    val raw: String? = null,
) : Exception(message) {

    /** The same error shape the rest of the SDK returns. */
    fun toErrorResponse(): ErrorResponse = ErrorResponse(
        error = -1,
        errorDescription = message,
        errorCode = errorCode,
        httpStatus = httpStatus,
        raw = raw,
    )

    /** The authorization server metadata named no authorization endpoint. */
    class NoAuthorizationEndpoint :
        AuthorizationException("This issuer's authorization server could not be identified")

    /**
     * The request reached the server and was refused.
     *
     * The body is read through [ErrorHandler], so a rejection carrying
     * `{"error":"invalid_request","error_description":"..."}` keeps the OAuth code as [errorCode]
     * instead of putting the whole blob in the message. Every issuer error shape the SDK has met is
     * handled there; this is the one place the authorization leg needs it.
     */
    class Rejected private constructor(
        message: String,
        errorCode: String?,
        status: Int?,
        raw: String?,
    ) : AuthorizationException(message, errorCode, status, raw) {

        companion object {
            operator fun invoke(status: Int?, detail: String?): Rejected {
                val parsed = detail?.takeIf { it.isNotBlank() }
                    ?.let { ErrorHandler.processError(it, status) }
                val message = parsed?.errorDescription?.takeIf { it.isNotBlank() }
                    ?: detail?.takeIf { it.isNotBlank() }
                    ?: "The authorization request was refused${status?.let { " (HTTP $it)" }.orEmpty()}"
                return Rejected(message, parsed?.errorCode, status, detail)
            }
        }
    }

    /** The request never completed -- network, DNS, timeout. */
    class RequestFailed(detail: String?) :
        AuthorizationException(detail?.takeIf { it.isNotBlank() } ?: "The authorization request failed")

    /**
     * The server answered, but with something this wallet cannot act on.
     *
     * The IAR extension's unknown `type` lands here, as does a response with no redirect at all --
     * both of which used to end in a silent null.
     */
    class Unusable(detail: String, status: Int? = null) :
        AuthorizationException(detail, httpStatus = status)
}
