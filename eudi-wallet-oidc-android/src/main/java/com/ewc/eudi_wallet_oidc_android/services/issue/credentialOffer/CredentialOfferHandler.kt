package com.ewc.eudi_wallet_oidc_android.services.issue.credentialOffer

import com.ewc.eudi_wallet_oidc_android.models.WrappedCredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest

interface CredentialOfferHandler {
    suspend fun processCredentialOffer(
        credentialOfferData: String
    ) : WrappedCredentialOffer?
}