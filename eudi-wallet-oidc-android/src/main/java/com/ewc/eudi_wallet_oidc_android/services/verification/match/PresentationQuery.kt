package com.ewc.eudi_wallet_oidc_android.services.verification.match

import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.PresentationDefinitionProcessor

/**
 * What the verifier is asking for, in one of the two query languages a request can carry.
 *
 * OpenID4VP 1.0 defines only [Dcql]. [PresentationDefinition] is Presentation Exchange from the
 * drafts and is kept for the verifiers still sending it.
 */
sealed class PresentationQuery {

    data class Dcql(val query: DCQL) : PresentationQuery()

    data class PresentationDefinition(
        val definition: com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition,
    ) : PresentationQuery()

    companion object {

        /** The request's query, DCQL first. Null when the request carries neither. */
        fun from(request: PresentationRequest): PresentationQuery? {
            request.dcqlQuery?.let { return Dcql(it) }
            request.presentationDefinition?.let {
                return PresentationDefinition(PresentationDefinitionProcessor.processPresentationDefinition(it))
            }
            return null
        }
    }
}
