package com.ewc.eudi_wallet_oidc_android.services.verification.clientIdSchemeHandling

import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.ClientIdScheme
import com.ewc.eudi_wallet_oidc_android.services.verification.clientIdSchemeHandling.WebOriginSchemeHandler

class ClientIdSchemeRequestHandler {
    /**
     * Handles a [WrappedPresentationRequest] by determining the client ID scheme
     * and delegating to the appropriate scheme-specific handler.
     *
     * The handler extracts the client ID scheme from the presentation request's clientId
     * and then routes the request to the corresponding scheme handler for processing.
     *
     * If the client ID scheme is missing or invalid, it returns a [WrappedPresentationRequest]
     * with an appropriate error response.
     *
     * Supported client ID schemes and their handlers:
     * - [ClientIdScheme.REDIRECT_URI] handled by [RedirectURISchemeHandler]
     * - [ClientIdScheme.DID] handled by [DIDSchemeHandler]
     * - [ClientIdScheme.VERIFIER_ATTESTATION] handled by [VerifierAttestationSchemeHandler]
     * - [ClientIdScheme.X509_SAN_DNS] handled by [X509SanDnsSchemeHandler]
     * - [ClientIdScheme.X509_SAN_URI] handled by [X509SanUriSchemeHandler]
     * - [ClientIdScheme.WEB_ORIGIN] handled by [WebOriginSchemeHandler]
     * - [ClientIdScheme.HTTPS] returns the original request unmodified
     *
     * For any other schemes, the original request is returned as is.
     *
     * @param presentationRequest The wrapped presentation request to handle.
     * @return The updated or validated [WrappedPresentationRequest] after processing
     *         or an error response if the client ID scheme is invalid or missing.
     */
    suspend fun handle(
        presentationRequest: WrappedPresentationRequest
    ): WrappedPresentationRequest {
        val clientId = presentationRequest.presentationRequest?.clientId ?: ""
        val clientIdScheme = presentationRequest.presentationRequest?.clientIdScheme ?: ClientIdParser.getClientIdScheme(clientId)
            ?: return WrappedPresentationRequest(
                presentationRequest = null,
                errorResponse = ErrorResponse(
                    error = null,
                    errorDescription = "Client ID scheme is missing or invalid"
                )
            )

        return when (clientIdScheme) {
            ClientIdScheme.REDIRECT_URI -> RedirectURISchemeHandler().update(presentationRequest)
            ClientIdScheme.DID -> DIDSchemeHandler().validate(presentationRequest)
            ClientIdScheme.VERIFIER_ATTESTATION -> VerifierAttestationSchemeHandler().validate(
                presentationRequest
            )

            ClientIdScheme.X509_SAN_DNS -> X509SanDnsSchemeHandler().validate(presentationRequest)
            ClientIdScheme.X509_SAN_URI -> X509SanUriSchemeHandler().validate(presentationRequest)
            ClientIdScheme.WEB_ORIGIN -> WebOriginSchemeHandler().validate(presentationRequest)
            ClientIdScheme.HTTPS -> presentationRequest
            ClientIdScheme.IAR -> presentationRequest
            else -> presentationRequest
        }
    }
}