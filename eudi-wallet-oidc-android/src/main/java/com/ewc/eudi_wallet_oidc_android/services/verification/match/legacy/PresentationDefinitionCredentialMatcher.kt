package com.ewc.eudi_wallet_oidc_android.services.verification.match.legacy

import com.ewc.eudi_wallet_oidc_android.services.verification.filterCredentials.PresentationDefinitionCredentialFilter
import com.ewc.eudi_wallet_oidc_android.services.verification.match.CredentialCandidate
import com.ewc.eudi_wallet_oidc_android.services.verification.match.CredentialMatch
import com.ewc.eudi_wallet_oidc_android.services.verification.match.CredentialMatcher
import com.ewc.eudi_wallet_oidc_android.services.verification.match.CredentialMatches
import com.ewc.eudi_wallet_oidc_android.services.verification.match.PresentationQuery
import com.ewc.eudi_wallet_oidc_android.services.verification.match.QueryEntry

/**
 * LEGACY, Presentation Exchange from the OpenID4VP drafts: one entry per input descriptor,
 * matched by the PEX library exactly as before. Submission requirements are not evaluated, so
 * every descriptor counts as required. Delete with the rest of `legacy/`.
 */
class PresentationDefinitionCredentialMatcher : CredentialMatcher {

    override fun supports(query: PresentationQuery): Boolean = query is PresentationQuery.PresentationDefinition

    override suspend fun match(query: PresentationQuery, credentials: List<String?>): CredentialMatches {
        val definition = (query as PresentationQuery.PresentationDefinition).definition
        val perDescriptor = PresentationDefinitionCredentialFilter()
            .filterCredentialsUsingPresentationDefinition(credentials, definition)

        val entries = definition.inputDescriptors.orEmpty().mapIndexed { index, descriptor ->
            val format = (descriptor.format?.takeIf { it.isNotEmpty() } ?: definition.format)?.keys?.firstOrNull()
            CredentialMatch(
                entry = QueryEntry(id = descriptor.id.orEmpty(), format = format, purpose = descriptor.purpose),
                candidates = perDescriptor.getOrNull(index).orEmpty().map { CredentialCandidate(credential = it) },
            )
        }
        val unsatisfied = entries.filter { !it.isSatisfied }.map { it.entry.id }
        return CredentialMatches(entries, satisfiable = unsatisfied.isEmpty(), unsatisfied = unsatisfied)
    }
}
