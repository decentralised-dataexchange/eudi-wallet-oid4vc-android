package com.ewc.eudi_wallet_oidc_android.services.issue.credential

import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.services.utils.ErrorHandler

/**
 * Why a credential request could not be completed.
 *
 * Internal: the resolver turns these into [CredentialOutcome.Failed], so a caller never catches.
 */
internal sealed class CredentialRequestException(
    message: String,
    val errorCode: String? = null,
    val httpStatus: Int? = null,
    val raw: String? = null,
) : Exception(message) {

    fun toErrorResponse(): ErrorResponse = ErrorResponse(
        error = -1,
        errorDescription = message,
        errorCode = errorCode,
        httpStatus = httpStatus,
        raw = raw,
    )

    /** The issuer metadata named no credential endpoint. */
    class NoCredentialEndpoint :
        CredentialRequestException("This issuer published no credential endpoint")

    /** The proof could not be built or signed. */
    class ProofFailed(detail: String) : CredentialRequestException(detail)

    /**
     * Section 8.2 makes `nonce` REQUIRED in the proof when the issuer publishes a Nonce Endpoint.
     * Sending one without it produces `invalid_proof` a round trip later, with nothing saying why.
     */
    class NoNonce :
        CredentialRequestException("This issuer requires a c_nonce in the proof and none could be obtained")

    /** The request reached the issuer and was refused. Read through [ErrorHandler]. */
    class Rejected private constructor(
        message: String,
        errorCode: String?,
        status: Int?,
        raw: String?,
    ) : CredentialRequestException(message, errorCode, status, raw) {

        companion object {
            operator fun invoke(status: Int?, detail: String?): Rejected {
                val parsed = detail?.takeIf { it.isNotBlank() }
                    ?.let { ErrorHandler.processError(it, status) }
                val message = parsed?.errorDescription?.takeIf { it.isNotBlank() }
                    ?: detail?.takeIf { it.isNotBlank() }
                    ?: "The credential request was refused${status?.let { " (HTTP $it)" }.orEmpty()}"
                return Rejected(message, parsed?.errorCode, status, detail)
            }
        }
    }

    /** The request never completed -- network, DNS, timeout. */
    class RequestFailed(detail: String?) :
        CredentialRequestException(detail?.takeIf { it.isNotBlank() } ?: "The credential request failed")

    /** The issuer answered with something this wallet cannot read. */
    class Unusable(detail: String, status: Int? = null) :
        CredentialRequestException(detail, httpStatus = status)
}

/** @see com.ewc.eudi_wallet_oidc_android.services.network.HttpCall */
internal fun credentialTransportFailure(detail: String?): Exception =
    CredentialRequestException.RequestFailed(detail)
