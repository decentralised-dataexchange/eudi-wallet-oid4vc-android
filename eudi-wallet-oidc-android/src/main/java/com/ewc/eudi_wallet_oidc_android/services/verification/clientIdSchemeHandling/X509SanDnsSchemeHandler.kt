package com.ewc.eudi_wallet_oidc_android.services.verification.clientIdSchemeHandling

import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.utils.X509SanRequestVerifier
import com.ewc.eudi_wallet_oidc_android.services.utils.X509VerifierNimbus

class X509SanDnsSchemeHandler : ClientIdSchemeHandler {
    /**
     * Validates the wrapped presentation request.
     *
     * Steps:
     * 1. Extracts the x5c certificate chain from the JWT request.
     * 2. Validates that the client ID is present in the DNS names of the certificate chain.
     * 3. Verifies the signature on the JWT using the extracted certificate chain.
     *
     * Returns the original wrapped request if validation succeeds, otherwise returns
     * an error response indicating the specific validation failure.
     *
     * @param wrappedPresentationRequest The wrapped presentation request to validate.
     * @return The original wrapped request if valid; otherwise, a wrapped request containing
     *         an error response describing the failure.
     */

    override suspend fun validate(wrappedPresentationRequest: WrappedPresentationRequest): WrappedPresentationRequest {
        val request = wrappedPresentationRequest.presentationRequest?.request
        if (request != null) {
            val x5cChain: List<String>? =
                X509SanRequestVerifier.Companion.instance.extractX5cFromJWT(request)

            if (x5cChain != null) {
                val isClientIdInDnsNames =
                    X509SanRequestVerifier.Companion.instance.validateClientIDInCertificate(
                        x5cChain,
                        wrappedPresentationRequest.presentationRequest?.clientId
                    )

                val isSignatureValid = X509VerifierNimbus().verifyJwtWithX5C(request)

                return if (isClientIdInDnsNames && isSignatureValid) {
                    wrappedPresentationRequest
                } else {
                    WrappedPresentationRequest(
                        presentationRequest = null,
                        errorResponse = ErrorResponse(
                            error = null,
                            errorDescription = "Invalid Request"
                        )
                    )
                }
            } else {
                return WrappedPresentationRequest(
                    presentationRequest = null,
                    errorResponse = ErrorResponse(
                        error = null,
                        errorDescription = "Missing x5c certificate chain"
                    )
                )
            }
        }

        return WrappedPresentationRequest(
            presentationRequest = null,
            errorResponse = ErrorResponse(
                error = null,
                errorDescription = "Missing JWT response string"
            )
        )
    }

    /**
     * Updates the wrapped presentation request.
     *
     * Currently no update logic is implemented for the X509San DNS scheme,
     * so this returns the request unmodified.
     *
     * @param wrappedPresentationRequest The wrapped presentation request to update.
     * @return The same wrapped presentation request without modifications.
     */
    override fun update(wrappedPresentationRequest: WrappedPresentationRequest): WrappedPresentationRequest {
        return wrappedPresentationRequest
    }

}