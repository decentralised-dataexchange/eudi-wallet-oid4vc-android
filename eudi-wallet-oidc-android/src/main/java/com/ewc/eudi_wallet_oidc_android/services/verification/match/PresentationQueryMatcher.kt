package com.ewc.eudi_wallet_oidc_android.services.verification.match

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.match.legacy.PresentationDefinitionCredentialMatcher

/**
 * Picks the matcher for the request's query language and runs it. Ordered, OpenID4VP 1.0 first.
 */
class PresentationQueryMatcher(
    private val matchers: List<CredentialMatcher> = defaultMatchers(),
) {

    suspend fun match(request: PresentationRequest, credentials: List<String?>): CredentialMatches {
        val query = PresentationQuery.from(request)
        if (query == null) {
            Logger.w(TAG, "The request carries neither dcql_query nor presentation_definition")
            return CredentialMatches.None
        }
        return match(query, credentials)
    }

    suspend fun match(query: PresentationQuery, credentials: List<String?>): CredentialMatches {
        val matcher = matchers.firstOrNull { it.supports(query) } ?: return CredentialMatches.None
        val matches = matcher.match(query, credentials)
        Logger.d(TAG, "Matched ${matches.entries.count { it.isSatisfied }} of ${matches.entries.size} entries, satisfiable=${matches.satisfiable}")
        return matches
    }

    companion object {
        private const val TAG = "PresentationQueryMatcher"

        fun defaultMatchers(): List<CredentialMatcher> = listOf(
            DcqlCredentialMatcher(),
            // --- legacy, safe to delete as a block ---
            PresentationDefinitionCredentialMatcher(),
        )
    }
}
