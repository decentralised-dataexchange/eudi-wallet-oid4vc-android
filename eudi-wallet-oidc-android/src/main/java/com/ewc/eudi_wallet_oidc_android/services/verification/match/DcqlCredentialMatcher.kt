package com.ewc.eudi_wallet_oidc_android.services.verification.match

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.CredentialList
import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.models.DcqlClaim
import com.ewc.eudi_wallet_oidc_android.services.dcql.DcqlValueMatcher

/**
 * OpenID4VP 1.0 section 6: one [CredentialMatch] per credential query, then the credential sets.
 *
 * Section 6.4.2: "Credentials not matching the respective constraints expressed within
 * credentials MUST NOT be returned, i.e., they are treated as if they would not exist in the
 * Wallet." A credential is a candidate for a query when its format and metadata match, it
 * satisfies the claims (section 6.4.1), it carries holder binding when required (section 6.1),
 * and it matches a trusted authority when any are given (section 6.1.1).
 */
class DcqlCredentialMatcher : CredentialMatcher {

    override fun supports(query: PresentationQuery): Boolean = query is PresentationQuery.Dcql

    override suspend fun match(query: PresentationQuery, credentials: List<String?>): CredentialMatches {
        val dcql = (query as PresentationQuery.Dcql).query
        val candidates = credentials.mapNotNull { CandidateCredential.decode(it) }
        val required = requiredEntryIds(dcql)

        val entries = dcql.credentials.orEmpty().map { credentialQuery ->
            val matched = candidates.mapNotNull { candidate -> candidateFor(credentialQuery, candidate) }
            CredentialMatch(
                entry = QueryEntry(
                    id = credentialQuery.id.orEmpty(),
                    format = credentialQuery.format,
                    required = required == null || credentialQuery.id in required,
                    multiple = credentialQuery.multiple,
                ),
                candidates = matched,
            )
        }
        val unsatisfied = unsatisfiedRequirements(dcql, entries)
        return CredentialMatches(entries, satisfiable = unsatisfied.isEmpty(), unsatisfied = unsatisfied)
    }

    private suspend fun candidateFor(query: CredentialList, candidate: CandidateCredential): CredentialCandidate? {
        if (!candidate.accepts(query.format)) return null
        if (!metadataMatches(query, candidate)) return null
        if (query.requireCryptographicHolderBinding && !candidate.holderBound) return null

        val claims = selectClaims(query, candidate) ?: return null

        val authorities = query.trustedAuthorities
        if (!authorities.isNullOrEmpty() && !TrustedAuthorityMatcher.matches(candidate, authorities)) return null

        return CredentialCandidate(credential = candidate.raw, claims = claims)
    }

    /** Appendix B: `vct_values` for SD-JWT VC, `doctype_value` for mdoc, `type_values` for W3C VC. */
    private fun metadataMatches(query: CredentialList, candidate: CandidateCredential): Boolean = when (candidate.format) {
        CandidateCredential.Format.SD_JWT -> {
            val wanted = query.meta?.vctValues
            wanted.isNullOrEmpty() || ClaimsPathPointer.selectValues(candidate.json, listOf("vct"))?.firstOrNull() in wanted
        }
        CandidateCredential.Format.MDOC -> {
            val wanted = query.meta?.doctypeValue
            wanted.isNullOrBlank() || candidate.docType == wanted
        }
        CandidateCredential.Format.JWT_VC -> {
            val options = query.meta?.typeValues
            if (options.isNullOrEmpty()) true
            else {
                val types = ClaimsPathPointer.selectValues(candidate.json, listOf("type"))?.firstOrNull()
                    .let { v -> (v as? List<*>)?.filterIsInstance<String>() ?: listOfNotNull(v as? String) }
                options.any { option -> option.all { it in types } }
            }
        }
    }

    /**
     * Section 6.4.1. Null when the credential cannot satisfy the query; otherwise the claims to
     * disclose: every claim, or the first claim set option the credential satisfies, or none when
     * the verifier asked for none.
     */
    private fun selectClaims(query: CredentialList, candidate: CandidateCredential): List<List<String?>>? {
        val claims = query.claims.orEmpty()
        if (claims.isEmpty()) return emptyList()

        val claimSets = query.claim_sets
        if (claimSets.isNullOrEmpty()) {
            return claims.map { claim -> pathOf(claim).takeIf { satisfies(claim, it, candidate) } ?: return null }
        }
        val byId = claims.filter { it.id != null }.associateBy { it.id!! }
        // Section 6.4.1: "the Wallet SHOULD return the first option that it can satisfy. If the
        // Wallet cannot satisfy any of the options, it MUST NOT return any claims."
        for (option in claimSets) {
            val selected = option.map { id -> byId[id] ?: return@map null }
            if (selected.isEmpty() || selected.any { it == null }) continue
            val paths = mutableListOf<List<String?>>()
            var satisfied = true
            for (claim in selected.filterNotNull()) {
                val path = pathOf(claim)
                if (!satisfies(claim, path, candidate)) { satisfied = false; break }
                paths.add(path)
            }
            if (satisfied) return paths
        }
        return null
    }

    private fun pathOf(claim: DcqlClaim): List<String?> {
        claim.path?.takeIf { it.isNotEmpty() }?.let { return it }
        // Draft mdoc shape: namespace and claim_name instead of a path.
        return listOfNotNull(claim.namespace, claim.claimName)
    }

    private fun satisfies(claim: DcqlClaim, path: List<String?>, candidate: CandidateCredential): Boolean {
        if (path.isEmpty()) return false
        val values = ClaimsPathPointer.selectValues(candidate.json, path)
            ?: if (candidate.format == CandidateCredential.Format.JWT_VC) {
                // W3C VCs keep subject claims under credentialSubject; the drafts addressed them without it.
                ClaimsPathPointer.selectValues(candidate.json, listOf("credentialSubject") + path)
            } else null
        if (values == null) return false
        // Section 6.3: the claim is returned only when its type and value match one of `values`.
        return claim.values.isNullOrEmpty() || values.any { DcqlValueMatcher.matchesClaimValues(claim, it) }
    }

    /**
     * Section 6.4.2: with credential_sets, only the entries named in a required set are
     * required. Null means every entry is required because there are no sets.
     */
    private fun requiredEntryIds(dcql: DCQL): Set<String>? {
        val sets = dcql.credential_sets ?: return null
        return sets.filter { it.required }.flatMap { set -> set.options.orEmpty().flatten() }.toSet()
    }

    private fun unsatisfiedRequirements(dcql: DCQL, entries: List<CredentialMatch>): List<String> {
        val satisfied = entries.filter { it.isSatisfied }.map { it.entry.id }.toSet()
        val sets = dcql.credential_sets
        if (sets == null) {
            return entries.filter { !it.isSatisfied }.map { it.entry.id }
        }
        return sets.mapIndexedNotNull { index, set ->
            if (!set.required) return@mapIndexedNotNull null
            val met = set.options.orEmpty().any { option -> option.isNotEmpty() && option.all { it in satisfied } }
            if (met) null else (set.purpose ?: "credential_sets[$index]")
        }.also { if (it.isNotEmpty()) Logger.d(TAG, "Required credential sets not satisfiable: $it") }
    }

    private companion object {
        const val TAG = "DcqlCredentialMatcher"
    }
}
