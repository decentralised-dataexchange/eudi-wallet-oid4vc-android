package com.ewc.eudi_wallet_oidc_android.services.dcql

import com.ewc.eudi_wallet_oidc_android.models.CredentialList
import com.ewc.eudi_wallet_oidc_android.models.CredentialSet
import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.models.DcqlClaim
import com.ewc.eudi_wallet_oidc_android.models.TrustedAuthority

/**
 * Structural validation of a DCQL query against OpenID4VP 1.0, sections 6 and 7 and
 * Appendix B. It runs once on the parsed request, before any stored credential is read,
 * so a query that breaks the specification is refused instead of being matched on a
 * best-effort basis.
 *
 * Only the shape of the query is checked here: required members, non-empty arrays, the
 * identifier character set, cross references between `claims` / `claim_sets` and
 * `credentials` / `credential_sets`, the format-specific `meta` members and the mdoc
 * two-component claim path. Whether the wallet holds matching credentials is decided
 * later by the filtering code. Unknown members are ignored by the parser, as the
 * specification requires.
 *
 * The parsed model stringifies non-string path components (integers, booleans), so a
 * path such as `["age", true]` cannot be told apart from `["age", "true"]` at this point.
 */
@Suppress("SENSELESS_COMPARISON")
object DcqlQueryValidator {

    private val ID_PATTERN = Regex("^[A-Za-z0-9_-]+$")
    private const val FORMAT_SD_JWT = "dc+sd-jwt"
    private const val FORMAT_MDOC = "mso_mdoc"
    private const val FORMAT_JWT_VC_JSON = "jwt_vc_json"
    private const val FORMAT_LDP_VC = "ldp_vc"
    private val SUPPORTED_FORMATS = setOf(FORMAT_SD_JWT, FORMAT_MDOC, FORMAT_JWT_VC_JSON, FORMAT_LDP_VC)
    private val TRUSTED_AUTHORITY_TYPES = setOf("aki", "etsi_tl", "openid_federation")

    /**
     * @return every violation found, in document order; an empty list means the query is valid.
     */
    fun validate(dcql: DCQL?): List<String> {
        val errors = mutableListOf<String>()
        if (dcql == null) {
            errors += "dcql_query is missing"
            return errors
        }

        val credentials = dcql.credentials
        if (credentials.isNullOrEmpty()) {
            errors += "credentials must be a non-empty array"
            return errors
        }

        val credentialIds = mutableSetOf<String>()
        credentials.forEachIndexed { index, credential ->
            validateCredentialQuery("credentials[$index]", credential, credentialIds, errors)
        }

        dcql.credential_sets?.let { sets ->
            if (sets.isEmpty()) {
                errors += "credential_sets must be a non-empty array when present"
            }
            sets.forEachIndexed { index, set ->
                validateCredentialSet("credential_sets[$index]", set, credentialIds, errors)
            }
        }

        return errors
    }

    private fun validateCredentialQuery(
        prefix: String,
        credential: CredentialList?,
        credentialIds: MutableSet<String>,
        errors: MutableList<String>
    ) {
        if (credential == null) {
            errors += "$prefix must be an object"
            return
        }

        val id = credential.id
        when {
            id.isNullOrBlank() -> errors += "$prefix.id is required"
            !ID_PATTERN.matches(id) -> errors += "$prefix.id must contain only letters, digits, '_' or '-'"
            !credentialIds.add(id) -> errors += "$prefix.id '$id' is not unique"
        }

        val format = credential.format
        when {
            format.isNullOrBlank() -> errors += "$prefix.format is required"
            format !in SUPPORTED_FORMATS -> errors += "$prefix.format '$format' is not supported"
        }

        val meta = credential.meta
        if (meta == null) {
            errors += "$prefix.meta is required"
        } else {
            when (format) {
                FORMAT_SD_JWT -> {
                    val vctValues = meta.vctValues
                    if (vctValues.isNullOrEmpty() || vctValues.any { it.isNullOrBlank() }) {
                        errors += "$prefix.meta.vct_values must be a non-empty array of strings for $FORMAT_SD_JWT"
                    }
                }
                FORMAT_MDOC -> {
                    if (meta.doctypeValue.isNullOrBlank()) {
                        errors += "$prefix.meta.doctype_value is required for $FORMAT_MDOC"
                    }
                }
                FORMAT_JWT_VC_JSON, FORMAT_LDP_VC -> {
                    val typeValues = meta.typeValues
                    if (typeValues.isNullOrEmpty() ||
                        typeValues.any { types -> types.isNullOrEmpty() || types.any { it.isNullOrBlank() } }
                    ) {
                        errors += "$prefix.meta.type_values must be a non-empty array of non-empty string arrays for $format"
                    }
                }
            }
        }

        val claims = credential.claims
        val claimSets = credential.claim_sets
        val claimIds = mutableSetOf<String>()
        if (claims != null) {
            if (claims.isEmpty()) {
                errors += "$prefix.claims must be a non-empty array when present"
            }
            claims.forEachIndexed { index, claim ->
                validateClaimsQuery(
                    "$prefix.claims[$index]", claim, format, claimSets != null, claimIds, errors
                )
            }
        }

        if (claimSets != null) {
            when {
                claims == null -> errors += "$prefix.claim_sets must not be present when claims is absent"
                claimSets.isEmpty() -> errors += "$prefix.claim_sets must be a non-empty array when present"
            }
            claimSets.forEachIndexed { index, set ->
                if (set.isNullOrEmpty()) {
                    errors += "$prefix.claim_sets[$index] must be a non-empty array"
                } else {
                    set.filter { it == null || it !in claimIds }.forEach { unknown ->
                        errors += "$prefix.claim_sets[$index] references unknown claim id '$unknown'"
                    }
                }
            }
        }

        credential.trustedAuthorities?.let { authorities ->
            if (authorities.isEmpty()) {
                errors += "$prefix.trusted_authorities must be a non-empty array when present"
            }
            authorities.forEachIndexed { index, authority ->
                validateTrustedAuthority("$prefix.trusted_authorities[$index]", authority, errors)
            }
        }
    }

    private fun validateClaimsQuery(
        prefix: String,
        claim: DcqlClaim?,
        format: String?,
        claimSetsPresent: Boolean,
        claimIds: MutableSet<String>,
        errors: MutableList<String>
    ) {
        if (claim == null) {
            errors += "$prefix must be an object"
            return
        }

        val id = claim.id
        when {
            id == null && claimSetsPresent -> errors += "$prefix.id is required when claim_sets is present"
            id == null -> Unit
            id.isBlank() || !ID_PATTERN.matches(id) ->
                errors += "$prefix.id must contain only letters, digits, '_' or '-'"
            !claimIds.add(id) -> errors += "$prefix.id '$id' is not unique"
        }

        val path = claim.path
        when {
            path.isNullOrEmpty() -> errors += "$prefix.path must be a non-empty array"
            format == FORMAT_MDOC && (path.size != 2 || path.any { it.isNullOrBlank() }) ->
                errors += "$prefix.path must have exactly two string components (namespace, element identifier) for $FORMAT_MDOC"
        }

        claim.values?.let { values ->
            when {
                values.isEmpty() -> errors += "$prefix.values must be a non-empty array when present"
                values.any { !isAllowedValue(it) } ->
                    errors += "$prefix.values may only contain strings, integers or booleans"
            }
        }
    }

    private fun isAllowedValue(value: Any?): Boolean = when (value) {
        is String, is Boolean -> true
        is Number -> value.toDouble() % 1.0 == 0.0
        else -> false
    }

    private fun validateCredentialSet(
        prefix: String,
        set: CredentialSet?,
        credentialIds: Set<String>,
        errors: MutableList<String>
    ) {
        if (set == null) {
            errors += "$prefix must be an object"
            return
        }
        val options = set.options
        if (options.isNullOrEmpty()) {
            errors += "$prefix.options must be a non-empty array"
            return
        }
        options.forEachIndexed { index, option ->
            if (option.isNullOrEmpty()) {
                errors += "$prefix.options[$index] must be a non-empty array"
            } else {
                option.filter { it == null || it !in credentialIds }.forEach { unknown ->
                    errors += "$prefix.options[$index] references unknown credential id '$unknown'"
                }
            }
        }
    }

    private fun validateTrustedAuthority(
        prefix: String,
        authority: TrustedAuthority?,
        errors: MutableList<String>
    ) {
        if (authority == null) {
            errors += "$prefix must be an object"
            return
        }
        val type = authority.type
        when {
            type.isNullOrBlank() -> errors += "$prefix.type is required"
            type !in TRUSTED_AUTHORITY_TYPES -> errors += "$prefix.type '$type' is not supported"
        }
        val values = authority.values
        if (values.isNullOrEmpty() || values.any { it.isNullOrBlank() }) {
            errors += "$prefix.values must be a non-empty array of strings"
        }
    }
}
