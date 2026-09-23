package com.ewc.eudi_wallet_oidc_android.services.issue.credential

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.AuthorizationDetail
import com.ewc.eudi_wallet_oidc_android.models.Credentials
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.IssueService
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession

/**
 * Which credential is being asked for.
 *
 * OpenID4VCI 1.0 section 8.2 gives two ways to name it and forbids using both:
 *
 *  - `credential_identifier` is "REQUIRED when an Authorization Details of type `openid_credential`
 *    was returned from the Token Response. It MUST NOT be used otherwise", and "when this parameter
 *    is used, the `credential_configuration_id` MUST NOT be present";
 *  - `credential_configuration_id` is "REQUIRED if a `credential_identifiers` parameter was not
 *    returned from the Token Response", with the mirror-image exclusion.
 *
 * A sealed type makes that exclusion unrepresentable. The previous implementation chose between
 * four `if`/`else` branches over the same nullable fields, where nothing stopped both being set.
 *
 * Note that **1.0 has no `format` parameter in the credential request** -- the format follows from
 * the configuration. [LegacyFormat] exists only for the pre-1.0 drafts and EBSI, which have neither
 * identifier, and is the single case to delete when draft support goes.
 */
sealed class CredentialSubject {

    /**
     * The offer entry this request is for.
     *
     * Carried rather than looked up. The previous implementation took an `index` into
     * `credentialOffer.credentials` alongside the offer itself -- two parameters that had to agree,
     * with nothing enforcing it, which is why it read `credentials.get(index)` unguarded. Naming
     * the credential by *position* is the mistake: what identifies it across the offer, the token
     * response's `authorization_details` and the issuer metadata is its configuration id.
     *
     * Null when the caller has no offer entry (a re-issuance, say). The proof then falls back to a
     * `jwk` header rather than guessing at a binding method, which is the honest degradation --
     * recovering the entry by matching on a type string and defaulting to the first credential
     * silently signs a proof for the wrong one.
     */
    abstract val offerCredential: Credentials?

    /** The token response returned `credential_identifiers`; section 8.2 requires this form. */
    data class ByIdentifier(
        val credentialIdentifier: String,
        override val offerCredential: Credentials? = null,
    ) : CredentialSubject()

    /** No `credential_identifiers` came back, so the configuration id names the credential. */
    data class ByConfiguration(
        val credentialConfigurationId: String,
        override val offerCredential: Credentials? = null,
    ) : CredentialSubject()

    /**
     * Pre-1.0 drafts and EBSI: `format` plus whichever of `types`, `vct` or `doctype` that
     * revision used.
     *
     * @param credentialDefinitionTypes carried as `credential_definition.type`, the EWC draft shape.
     * @param types carried at the top level, the EBSI draft shape.
     */
    data class LegacyFormat(
        val format: String?,
        val types: List<String>? = null,
        val credentialDefinitionTypes: List<String>? = null,
        val vct: String? = null,
        val docType: String? = null,
        override val offerCredential: Credentials? = null,
    ) : CredentialSubject()

    companion object {

        /**
         * Which form section 8.2 requires for [credential], given what the token response returned.
         *
         * The rule is the specification's, so it belongs here rather than in every caller:
         *
         *  - `credential_identifier` is "REQUIRED when an Authorization Details of type
         *    `openid_credential` was returned from the Token Response";
         *  - `credential_configuration_id` is "REQUIRED if a `credential_identifiers` parameter was
         *    not returned";
         *  - and drafts, which predate both, name the credential by `format` plus their own type
         *    field.
         *
         * The 1.0-versus-draft test is whether the issuer publishes a nonce endpoint. That is a
         * proxy rather than a version field, and a deliberate one: an earlier gate on "the token
         * response carried no c_nonce" excluded issuers that publish a nonce endpoint *and* return
         * a c_nonce with the token -- servers exist that do both -- and they reject the draft body with
         * "Invalid request format".
         */
        fun of(
            session: IssuanceSession,
            token: TokenResponse,
            credential: Credentials?,
        ): CredentialSubject {
            val details = token.authorizationDetails.orEmpty().filter { it.type == OPENID_CREDENTIAL }

            // Only take a detail that names *this* credential. Falling back to the first one when
            // nothing matched sends another credential's `credential_identifier`, which the issuer
            // answers with an error or a 500 -- and only for the credentials after the first, so it
            // looks like one bad credential rather than a bad rule. A single detail is unambiguous
            // and is the one-credential case.
            val detail = details.firstOrNull { matches(it, credential) } ?: details.singleOrNull()
            if (detail == null && details.size > 1) {
                Logger.d(
                    TAG,
                    "no authorization_details entry names ${credential?.types?.firstOrNull()}; " +
                        "naming it by configuration id instead of borrowing " +
                        "${details.first().credentialConfigurationId}",
                )
            }

            detail?.credentialIdentifiers?.firstOrNull()?.takeIf { it.isNotBlank() }?.let {
                Logger.d(TAG, "credential_identifier=$it for ${credential?.types?.firstOrNull()}")
                return ByIdentifier(it, credential)
            }

            val publishesNonceEndpoint = !session.issuerConfig?.nonceEndpoint.isNullOrBlank()
            if (publishesNonceEndpoint) {
                val configurationId = detail?.credentialConfigurationId?.takeIf { it.isNotBlank() }
                    ?: credential?.types?.firstOrNull()?.takeIf { it.isNotBlank() }
                if (configurationId != null) {
                    Logger.d(TAG, "credential_configuration_id=$configurationId")
                    return ByConfiguration(configurationId, credential)
                }
            }

            return legacyFor(session, credential).also {
                Logger.d(TAG, "draft shape: format=${it.format} vct=${it.vct} doctype=${it.docType}")
            }
        }

        /** The pre-1.0 shapes, chosen the way `buildCredentialRequest` always chose them. */
        private fun legacyFor(session: IssuanceSession, credential: Credentials?): LegacyFormat {
            val issuerConfig = session.issuerConfig
            val service = IssueService()
            val types = credential?.types ?: credential?.doctype?.let { arrayListOf(it) } ?: arrayListOf()
            val format = service.getFormatFromIssuerConfig(issuerConfig, types.lastOrNull())

            if (format == MSO_MDOC) {
                return LegacyFormat(
                    format = format,
                    docType = credential?.doctype ?: types.lastOrNull(),
                    offerCredential = credential,
                )
            }

            // A map-shaped `credentials_supported` is the 1.0-era metadata that names types under
            // `credential_definition`; a list is the EBSI-era shape that carries them at the top.
            val definitionShaped = issuerConfig?.credentialsSupported is Map<*, *>
            if (!definitionShaped) {
                return LegacyFormat(format = format, types = types, offerCredential = credential)
            }

            return when (
                val declared = service.getTypesFromIssuerConfig(
                    issuerConfig,
                    type = types.lastOrNull() ?: "",
                    version = session.offerVersion,
                )
            ) {
                is String -> LegacyFormat(format = format, vct = declared, offerCredential = credential)

                is ArrayList<*> -> LegacyFormat(
                    format = format,
                    credentialDefinitionTypes = declared.filterIsInstance<String>(),
                    offerCredential = credential,
                )

                else -> LegacyFormat(
                    format = format,
                    credentialDefinitionTypes = types,
                    offerCredential = credential,
                )
            }
        }

        /** Whether an authorization detail names this offer entry. */
        private fun matches(detail: AuthorizationDetail, credential: Credentials?): Boolean {
            val type = credential?.types?.firstOrNull() ?: return false
            return detail.credentialConfigurationId == type ||
                detail.credentialIdentifiers?.contains(type) == true
        }

        private const val TAG = "CredentialSubject"
        private const val OPENID_CREDENTIAL = "openid_credential"
        private const val MSO_MDOC = "mso_mdoc"
    }
}
