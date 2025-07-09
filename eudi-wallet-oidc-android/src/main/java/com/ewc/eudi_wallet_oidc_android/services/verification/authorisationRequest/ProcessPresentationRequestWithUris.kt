package com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.clientIdSchemeHandling.ClientIdSchemeRequestHandler

object ProcessPresentationRequestWithUris {

    suspend fun processPresentationRequest(
        json: PresentationRequest?
    ): WrappedPresentationRequest {
        if (json?.presentationDefinition == null && !json?.presentationDefinitionUri.isNullOrBlank()) {
            val resolvedPresentationDefinition =
                PresentationDefinitionRepository.getPresentationDefinitionFromUri(json?.presentationDefinitionUri)
            json?.presentationDefinition = resolvedPresentationDefinition
        }
        if (json?.clientMetaDetails == null && !json?.clientMetadataUri.isNullOrBlank()) {
            val resolvedClientMetaDetails =
                ClientMetadataRepository.getClientMetaDataFromUri(json?.clientMetadataUri)
            json?.clientMetaDetails = resolvedClientMetaDetails
        }

        return validatePresentationRequest(
            WrappedPresentationRequest(
                presentationRequest = json
            )
        )
    }

    private suspend fun validatePresentationRequest(
        presentationRequest: WrappedPresentationRequest
    ): WrappedPresentationRequest {
        val wrappedPresentationRequest =
            ClientIdSchemeRequestHandler().handle(presentationRequest)
        return wrappedPresentationRequest
    }
}