package com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest

interface AuthorisationRequestHandler {
    suspend fun processAuthorisationRequest(
        authorisationRequestData: String
    ) : WrappedPresentationRequest
}