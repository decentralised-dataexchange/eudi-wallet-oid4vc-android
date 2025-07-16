package com.ewc.eudi_wallet_oidc_android.services.verification.clientIdSchemeHandling

import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest

class WebOriginSchemeHandler : ClientIdSchemeHandler {

    /**
     * Validates the wrapped presentation request.
     *
     * Currently, no validation is performed for the Web Origin scheme.
     *
     * @param wrappedPresentationRequest The wrapped presentation request to validate.
     * @return The same wrapped presentation request without modifications.
     */
    override suspend fun validate(wrappedPresentationRequest: WrappedPresentationRequest): WrappedPresentationRequest {
        return wrappedPresentationRequest
    }

    /**
     * Updates the wrapped presentation request.
     *
     * Currently, no update is performed for the Web Origin scheme.
     *
     * @param wrappedPresentationRequest The wrapped presentation request to update.
     * @return The same wrapped presentation request without modifications.
     */
    override fun update(wrappedPresentationRequest: WrappedPresentationRequest): WrappedPresentationRequest {
        return wrappedPresentationRequest
    }
}