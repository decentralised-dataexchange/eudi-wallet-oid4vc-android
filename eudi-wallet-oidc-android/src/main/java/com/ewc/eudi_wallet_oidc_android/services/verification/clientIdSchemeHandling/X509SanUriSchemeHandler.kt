package com.ewc.eudi_wallet_oidc_android.services.verification.clientIdSchemeHandling

import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.utils.X509SanRequestVerifier
import com.ewc.eudi_wallet_oidc_android.services.utils.X509VerifierNimbus

class X509SanUriSchemeHandler : ClientIdSchemeHandler {
    /**
     * Validates the wrapped presentation request.
     *
     * Currently, no validation is performed for the X509 SAN URI scheme.
     *
     * @param wrappedPresentationRequest The wrapped presentation request to validate.
     * @return The same wrapped presentation request without modifications.
     */
    override suspend fun validate(wrappedPresentationRequest: WrappedPresentationRequest): WrappedPresentationRequest {
//        val request = wrappedPresentationRequest.presentationRequest?.request
//        if (request != null) {
//            val x5cChain: List<String>? =
//                X509SanRequestVerifier.Companion.instance.extractX5cFromJWT(request)
//            if (x5cChain != null) {
//                val isClientIdValid = X509SanRequestVerifier.instance.validateClientIDInCertificate(
//                    x5cChain,
//                    wrappedPresentationRequest.presentationRequest?.clientId
//                )
//                val isSignatureValid = X509VerifierNimbus().verifyJwtWithX5C(request)
//
//                return if (isClientIdValid && isSignatureValid) {
//                    wrappedPresentationRequest
//                } else {
//                    WrappedPresentationRequest(
//                        presentationRequest = null,
//                        errorResponse = ErrorResponse(
//                            error = null,
//                            errorDescription = "Invalid Request"
//                        )
//                    )
//                }
//
//            } else {
//                return WrappedPresentationRequest(
//                    presentationRequest = null,
//                    errorResponse = ErrorResponse(
//                        error = null,
//                        errorDescription = "Missing x5c certificate chain"
//                    )
//                )
//            }
//
//        }
//
//        return WrappedPresentationRequest(
//            presentationRequest = null,
//            errorResponse = ErrorResponse(
//                error = null,
//                errorDescription = "Missing JWT response string"
//            )
//        )
     return wrappedPresentationRequest
    }

    /**
     * Updates the wrapped presentation request.
     *
     * Currently, no update is performed for the X509 SAN URI scheme.
     *
     * @param wrappedPresentationRequest The wrapped presentation request to update.
     * @return The same wrapped presentation request without modifications.
     */
    override fun update(wrappedPresentationRequest: WrappedPresentationRequest): WrappedPresentationRequest {
        return wrappedPresentationRequest
    }
}