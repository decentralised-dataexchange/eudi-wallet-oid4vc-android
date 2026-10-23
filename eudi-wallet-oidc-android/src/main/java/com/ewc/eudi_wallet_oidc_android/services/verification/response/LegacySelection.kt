package com.ewc.eudi_wallet_oidc_android.services.verification.response

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.PresentationDefinitionProcessor
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.SelectedCredential
import com.nimbusds.jose.jwk.JWK

/**
 * The previous API's contract: credentials and keys arrive as lists aligned by position with the
 * query's entries. Turned into [SelectedCredential]s named by entry id, once, here.
 */
internal object LegacySelection {

    /**
     * Null when the groups cannot be mapped onto the DCQL query, which the previous API answered
     * with an empty response.
     */
    fun from(
        request: PresentationRequest,
        groups: List<List<String>>?,
        keys: List<List<JWK?>>?,
        holderKey: JWK?,
    ): List<SelectedCredential>? {
        val entryIds: List<String> = request.dcqlQuery?.credentials?.let { queries ->
            if (groups == null || queries.size != groups.size) return null
            queries.map { it.id ?: "" }
        } ?: PresentationDefinitionProcessor.processPresentationDefinition(request.presentationDefinition)
            .inputDescriptors?.map { it.id ?: "" }.orEmpty()

        return groups.orEmpty().flatMapIndexed { entryIndex, group ->
            group.filter { it.isNotBlank() }.mapIndexed { credentialIndex, credential ->
                SelectedCredential(
                    entryId = entryIds.getOrNull(entryIndex) ?: "",
                    credential = credential,
                    key = keys?.getOrNull(entryIndex)?.getOrNull(credentialIndex) ?: holderKey,
                )
            }
        }
    }
}
