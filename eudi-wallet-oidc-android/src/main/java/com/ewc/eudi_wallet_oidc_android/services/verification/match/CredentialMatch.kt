package com.ewc.eudi_wallet_oidc_android.services.verification.match

/**
 * One row of the query the user picks a credential for: a DCQL credential query, or a
 * Presentation Exchange input descriptor. Identified by [id], never by position.
 */
data class QueryEntry(
    /** The DCQL credential query `id` or the input descriptor `id`; the key of the response's `vp_token`. */
    val id: String,
    /** The credential format identifier the entry asks for. */
    val format: String?,
    /** False when the entry only appears in optional credential sets, or in none (section 6.4.2). */
    val required: Boolean = true,
    /** Section 6.1 `multiple`: whether more than one credential may be returned for this entry. */
    val multiple: Boolean = false,
    val purpose: String? = null,
)

/**
 * A stored credential that satisfies a [QueryEntry].
 *
 * @param credential the credential exactly as the host handed it in, so it can be looked up again.
 * @param claims the claims path pointers to disclose: the claim set the wallet chose (section
 *   6.4.1), or every requested claim when there are no claim sets. Empty means the verifier asked
 *   for no selectively disclosable claims and only the mandatory part is presented.
 */
data class CredentialCandidate(
    val credential: String,
    val claims: List<List<String?>> = emptyList(),
)

data class CredentialMatch(
    val entry: QueryEntry,
    val candidates: List<CredentialCandidate>,
) {
    val isSatisfied: Boolean get() = candidates.isNotEmpty()
}

/**
 * The answer to a presentation query over the wallet's credentials.
 *
 * @param entries one per query entry, in the verifier's order, each with its candidates.
 * @param satisfiable section 6.4.2: every required entry, or every required credential set, has
 *   at least one candidate. When false the wallet should tell the user before any selection.
 * @param unsatisfied the ids of the required entries, or the purposes or indexes of the required
 *   credential sets, that nothing in the wallet satisfies.
 */
data class CredentialMatches(
    val entries: List<CredentialMatch>,
    val satisfiable: Boolean,
    val unsatisfied: List<String> = emptyList(),
) {

    fun candidatesFor(entryId: String): List<CredentialCandidate> =
        entries.firstOrNull { it.entry.id == entryId }?.candidates.orEmpty()

    /** The shape of the previous API: candidate credentials per entry, in query order. */
    fun asLegacyLists(): List<List<String>> =
        entries.map { match -> match.candidates.map { it.credential } }

    companion object {
        /** A request with no query, or one no matcher understands. */
        val None = CredentialMatches(entries = emptyList(), satisfiable = false)
    }
}
