package com.ewc.eudi_wallet_oidc_android.services.verification.clientIdSchemeHandling

import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.SignatureValidator
import com.ewc.eudi_wallet_oidc_android.services.exceptions.SignatureException

class DIDSchemeHandler : ClientIdSchemeHandler {
    /**
     * Validates the signature of the presentation request using a [SignatureValidator].
     *
     * Attempts to validate the signature present in the `request` field of the
     * wrapped presentation request. If the signature validation fails or throws
     * a [SignatureException], the function returns a [WrappedPresentationRequest]
     * with an error response indicating signature validation failure.
     *
     * @param wrappedPresentationRequest The wrapped presentation request to validate.
     * @return The original wrapped request if the signature is valid; otherwise,
     *         a wrapped request containing an error response.
     */

    override suspend fun validate(wrappedPresentationRequest: WrappedPresentationRequest): WrappedPresentationRequest {
        val isSignatureValid = try {
            SignatureValidator().validateSignature(
                wrappedPresentationRequest.presentationRequest?.request,
                jwksUri = null
            )
        } catch (e: SignatureException) {
            false
        }

        if (!isSignatureValid) {
            return WrappedPresentationRequest(
                presentationRequest = null,
                errorResponse = ErrorResponse(
                    error = null,
                    errorDescription = "Authorization request signature validation failed"
                )
            )
        }
        return wrappedPresentationRequest
    }

    /**
     * Updates the wrapped presentation request.
     *
     * For the DID scheme, no update logic is currently implemented, so
     * this function returns the wrapped presentation request as is.
     *
     * @param wrappedPresentationRequest The wrapped presentation request to update.
     * @return The same wrapped presentation request without modifications.
     */
    override fun update(wrappedPresentationRequest: WrappedPresentationRequest): WrappedPresentationRequest {
        return wrappedPresentationRequest
    }
}