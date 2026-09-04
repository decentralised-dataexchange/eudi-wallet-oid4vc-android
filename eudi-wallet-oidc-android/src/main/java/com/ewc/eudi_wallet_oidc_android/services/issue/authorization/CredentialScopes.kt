package com.ewc.eudi_wallet_oidc_android.services.issue.authorization

import com.google.gson.Gson
import org.json.JSONObject

/**
 * The `scope` values an issuer declares for the credentials an offer names.
 *
 * OpenID4VCI 1.0 section 5.1.2: "When the flow starts with a Credential Offer, the Wallet can use
 * the `credential_configuration_ids` parameter values to identify object(s) in the
 * `credential_configurations_supported` map in the Credential Issuer metadata parameter and **use
 * the `scope` parameter value from that object**."
 *
 * Nothing in this SDK read that value before; the authorization request has always sent a fixed
 * `openid`. Reading it is behind [AuthorizationRequestPolicy.useCredentialScopes] because it
 * changes a parameter the authorization server acts on -- see the policy for why that is off by
 * default.
 *
 * Only meaningful for 1.0 metadata, where `credential_configurations_supported` is an object keyed
 * by configuration id. Draft metadata is an array of credential objects with no such key, so this
 * returns nothing for it and drafts keep the scope they have always sent.
 */
internal object CredentialScopes {

    fun forOffer(session: IssuanceSession): List<String> {
        val issuerConfig = session.issuerConfig ?: return emptyList()
        val configurationIds = session.credentialOffer?.credentials
            ?.mapNotNull { it.types?.firstOrNull() }
            ?.filter { it.isNotBlank() }
            .orEmpty()
        if (configurationIds.isEmpty()) return emptyList()

        // The model merges 1.0's credential_configurations_supported and the draft array into one
        // field, so read it the same way getFormatFromIssuerConfig does.
        val supported = runCatching {
            JSONObject(Gson().toJson(issuerConfig)).optJSONObject("credentials_supported")
        }.getOrNull() ?: return emptyList()

        return configurationIds
            .mapNotNull { id -> supported.optJSONObject(id)?.optString("scope")?.takeIf { it.isNotBlank() } }
            .distinct()
    }
}
