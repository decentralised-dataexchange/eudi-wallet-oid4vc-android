package com.ewc.eudi_wallet_oidc_android.services.issue.authorization.details

import com.ewc.eudi_wallet_oidc_android.models.AuthorizationDetails
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.details.legacy.DraftAuthorizationDetailsBuilder
import com.google.gson.Gson

/**
 * Builds the `authorization_details` parameter, RFC 9396 with the `openid_credential` type
 * OpenID4VCI 1.0 section 5.1.1 defines.
 *
 * Was two overloaded private methods on `IssueService` with a version ladder between them and
 * thirty-three lines of commented-out alternatives. Draft support is quarantined in
 * [DraftAuthorizationDetailsBuilder] so it can be removed as a block, like the offer parsers.
 *
 * Section 5.1.1 requires, for the 1.0 type:
 *  - `type`, "MUST be set to `openid_credential`" -- the model defaults to it;
 *  - `credential_configuration_id`, "a unique identifier of the Credential being described in the
 *    `credential_configurations_supported` map";
 *  - `locations`, which **"MUST be set to the Credential Issuer Identifier value"** when the issuer
 *    metadata carries an `authorization_servers` parameter. That one was missing: the 1.0 path
 *    never set `locations` at all, only the draft paths did. Section 6.1 restates the same rule for
 *    the token request.
 *
 * `format` and `doctype` are deliberately absent from the 1.0 details: 1.0 carries them in the
 * credential configuration the id points at, not in the request.
 */
class AuthorizationDetailsBuilder(
    private val gson: Gson = Gson(),
    private val draft: DraftAuthorizationDetailsBuilder = DraftAuthorizationDetailsBuilder(gson),
) {

    /**
     * @param format only used by the draft builder and for the mdoc special case.
     * @param docType only used by the draft builder.
     * @param types the credential's type array from `getTypesFromCredentialOffer`; drafts only.
     */
    fun build(
        session: IssuanceSession,
        format: String?,
        docType: String?,
        types: ArrayList<String>,
    ): String {
        if (session.offerVersion == DRAFT_VERSION) {
            return draft.build(session, format, docType, types)
        }

        val details = session.credentialOffer?.credentials.orEmpty().map { credential ->
            AuthorizationDetails(
                credentialConfigurationId = credential.types?.firstOrNull(),
                locations = locationsFor(session),
            )
        }
        return gson.toJson(details)
    }

    /**
     * "If the Credential Issuer metadata contains an `authorization_servers` parameter, the
     * authorization detail's `locations` common data field MUST be set to the Credential Issuer
     * Identifier value."
     *
     * Set only under that condition, so an issuer that is its own authorization server keeps
     * receiving the leaner request it does today.
     */
    private fun locationsFor(session: IssuanceSession): ArrayList<String>? {
        val declaresAuthorizationServers =
            session.issuerConfig?.authorizationServers?.any { it.isNotBlank() } == true
        if (!declaresAuthorizationServers) return null

        val issuer = session.credentialOffer?.credentialIssuer
            ?: session.issuerConfig?.credentialIssuer
            ?: return null
        return arrayListOf(issuer)
    }

    private companion object {
        const val DRAFT_VERSION = 1
    }
}
