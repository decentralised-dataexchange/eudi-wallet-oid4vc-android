package com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest

import com.ewc.eudi_wallet_oidc_android.models.ErrorCodes
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.dcql.DcqlQueryValidator
import com.ewc.eudi_wallet_oidc_android.services.verification.clientIdSchemeHandling.ClientIdSchemeRequestHandler

object ProcessPresentationRequestWithUris {

    suspend fun processPresentationRequest(
        json: PresentationRequest?
    ): WrappedPresentationRequest {
        // Every request entry point (by value, request, request_uri, JWT, IAR) funnels through here,
        // so a DCQL query that breaks OpenID4VP 1.0 is refused once, before any URI is resolved
        // or any stored credential is read.
        json?.dcqlQuery?.let { dcql ->
            val violations = DcqlQueryValidator.validate(dcql)
            if (violations.isNotEmpty()) {
                return invalidDcqlQuery(violations.joinToString("; "))
            }
        }
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

    fun invalidDcqlQuery(reason: String?): WrappedPresentationRequest =
        WrappedPresentationRequest(
            presentationRequest = null,
            errorResponse = ErrorResponse(
                error = ErrorCodes.INVALID_DCQL_QUERY,
                errorDescription = "Invalid DCQL query: $reason"
            )
        )

    private suspend fun validatePresentationRequest(
        presentationRequest: WrappedPresentationRequest
    ): WrappedPresentationRequest {
//        val wrappedPresentationRequest =
//            ClientIdSchemeRequestHandler().handle(presentationRequest)
        return presentationRequest
    }
}