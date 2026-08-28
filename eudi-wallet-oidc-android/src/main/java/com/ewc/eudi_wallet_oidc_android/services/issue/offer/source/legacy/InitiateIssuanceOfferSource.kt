package com.ewc.eudi_wallet_oidc_android.services.issue.offer.source.legacy

import com.ewc.eudi_wallet_oidc_android.services.issue.offer.CredentialOfferException
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.CredentialOfferPolicy
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.OfferUri
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.source.CredentialOfferSource
import com.google.gson.JsonArray
import com.google.gson.JsonObject

/**
 * LEGACY -- pre-OpenID4VCI. The EBSI "initiate issuance" link, which spreads the offer across
 * query parameters instead of carrying a JSON document:
 *
 * `openid://initiate_issuance?issuer=...&credential_type=...&pre-authorized_code=...&user_pin_required=true`
 *
 * Rewritten here into a draft-shaped offer document so the rest of the pipeline is unaware of it.
 * Delete this file and its registry entry to drop support.
 */
class InitiateIssuanceOfferSource : CredentialOfferSource {

    override val name: String = "initiate_issuance"

    override fun supports(data: String): Boolean =
        data.contains(MARKER, ignoreCase = true) && !OfferUri.queryParam(data, ISSUER).isNullOrBlank()

    override suspend fun retrieve(data: String, policy: CredentialOfferPolicy): String {
        val issuer = OfferUri.queryParam(data, ISSUER)
        if (issuer.isNullOrBlank()) throw CredentialOfferException.NoOffer()

        val offer = JsonObject().apply {
            addProperty("credential_issuer", issuer)

            val types = JsonArray().apply {
                OfferUri.queryParam(data, CREDENTIAL_TYPE)
                    ?.split(' ')
                    ?.filter { it.isNotBlank() }
                    ?.forEach { add(it) }
            }
            add("credentials", types)

            val grants = JsonObject()
            OfferUri.queryParam(data, PRE_AUTHORIZED_CODE)?.takeIf { it.isNotBlank() }?.let { code ->
                grants.add(
                    PRE_AUTHORIZED_GRANT,
                    JsonObject().apply {
                        addProperty("pre-authorized_code", code)
                        addProperty(
                            "user_pin_required",
                            OfferUri.queryParam(data, USER_PIN_REQUIRED)?.toBoolean() ?: false,
                        )
                    },
                )
            }
            OfferUri.queryParam(data, ISSUER_STATE)?.takeIf { it.isNotBlank() }?.let { state ->
                grants.add(
                    "authorization_code",
                    JsonObject().apply { addProperty("issuer_state", state) },
                )
            }
            if (grants.size() > 0) add("grants", grants)
        }

        return offer.toString()
    }

    private companion object {
        const val MARKER = "initiate_issuance"
        const val ISSUER = "issuer"
        const val CREDENTIAL_TYPE = "credential_type"
        const val PRE_AUTHORIZED_CODE = "pre-authorized_code"
        const val USER_PIN_REQUIRED = "user_pin_required"
        const val ISSUER_STATE = "issuer_state"
        const val PRE_AUTHORIZED_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    }
}
