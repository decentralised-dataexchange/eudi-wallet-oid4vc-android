package com.ewc.eudi_wallet_oidc_android.services.verification.clientIdSchemeHandling

import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.ResponseModes

class RedirectURISchemeHandler : ClientIdSchemeHandler {

    override suspend fun validate(wrappedPresentationRequest: WrappedPresentationRequest): WrappedPresentationRequest {
        return wrappedPresentationRequest
    }

    /**
     * Updates the `redirectUri` in the presentation request using the scheme-specific part of the clientId,
     * if `redirectUri` is currently null or empty.
     *
     * @param wrappedPresentationRequest The wrapped presentation request that may need updating.
     * @return The updated WrappedPresentationRequest.
     */
    override fun update(wrappedPresentationRequest: WrappedPresentationRequest): WrappedPresentationRequest {

        val clientIdScheme = ClientIdParser.getSchemeSpecificIdentifier(
            wrappedPresentationRequest.presentationRequest?.clientId ?: ""
        )
        //if responseMode directpost/directpost_jwt -> update response uri else update redirect uri
        val responseMode = wrappedPresentationRequest.presentationRequest?.responseMode

        val responseModeEnum = responseMode?.let { ResponseModes.fromString(it) }
        if (responseModeEnum == ResponseModes.DIRECT_POST ||
            responseModeEnum == ResponseModes.DIRECT_POST_JWT
        ) {
            wrappedPresentationRequest.presentationRequest?.responseUri =
                wrappedPresentationRequest.presentationRequest?.responseUri ?: clientIdScheme
        } else {
            wrappedPresentationRequest.presentationRequest?.redirectUri =
                wrappedPresentationRequest.presentationRequest?.redirectUri ?: clientIdScheme

        }


        return wrappedPresentationRequest
    }
}