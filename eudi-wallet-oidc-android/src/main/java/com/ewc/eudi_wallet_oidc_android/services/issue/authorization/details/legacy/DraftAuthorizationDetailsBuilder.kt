package com.ewc.eudi_wallet_oidc_android.services.issue.authorization.details.legacy

import com.ewc.eudi_wallet_oidc_android.models.AuthorizationDetails
import com.ewc.eudi_wallet_oidc_android.models.CredentialTypeDefinition
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.google.gson.Gson

/**
 * LEGACY -- pre-1.0 draft `authorization_details`.
 *
 * Drafts named the credential in the request itself rather than by a configuration id: an mdoc
 * request carried `doctype`, an EBSI request carried `types`, and an EWC request carried a
 * `credential_definition`. Which of the two latter shapes is used is decided by whether the offer
 * carried a `trust_framework`, which is EBSI's marker.
 *
 * `locations` is set unconditionally here, as it always was for drafts. Behaviour is unchanged.
 *
 * Delete this file and its use in `AuthorizationDetailsBuilder` to drop draft support.
 */
class DraftAuthorizationDetailsBuilder(private val gson: Gson = Gson()) {

    /**
     * @param types the credential's own type array, as `getTypesFromCredentialOffer` produces it.
     *   Passed in rather than derived here: for an EBSI offer this is a hierarchy
     *   (`["VerifiableCredential", "VerifiableAttestation", ...]`) belonging to one credential, and
     *   the whole array is what the draft request carries.
     */
    fun build(
        session: IssuanceSession,
        format: String?,
        docType: String?,
        types: ArrayList<String>,
    ): String {
        val offer = session.credentialOffer
        val locations = arrayListOf(offer?.credentialIssuer ?: "")

        if (format == "mso_mdoc" && docType != null) {
            return gson.toJson(
                arrayListOf(
                    AuthorizationDetails(format = format, doctype = docType, locations = locations)
                )
            )
        }

        // No trust framework means the EWC flavour, which describes the credential with a
        // credential_definition rather than a bare types array.
        val isEwcFlavour = runCatching { offer?.credentials?.get(0)?.trustFramework == null }
            .getOrDefault(true)

        val details = if (isEwcFlavour) {
            AuthorizationDetails(
                format = format,
                locations = locations,
                credentialDefinition = CredentialTypeDefinition(type = types),
            )
        } else {
            AuthorizationDetails(format = format, types = types, locations = locations)
        }
        return gson.toJson(arrayListOf(details))
    }
}
