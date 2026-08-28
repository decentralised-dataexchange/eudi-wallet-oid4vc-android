package com.ewc.eudi_wallet_oidc_android.services.issue.offer.parser

import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.v2.CredentialOfferEwcV2
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.CredentialOfferSpecVersion
import com.google.gson.Gson
import com.google.gson.JsonObject

/**
 * OpenID4VCI 1.0 -- the revision this SDK targets.
 *
 * Recognised by `credential_configuration_ids`, which 1.0 makes REQUIRED and which no draft
 * revision uses. That single key is the whole discriminator, so detection does not depend on
 * anything else in the document.
 */
class OpenId4VciV1OfferParser(
    private val gson: Gson = Gson(),
) : CredentialOfferParser {

    override val specVersion: CredentialOfferSpecVersion = CredentialOfferSpecVersion.V1_0

    override fun supports(json: JsonObject): Boolean =
        json.get(CONFIGURATION_IDS)?.isJsonArray == true

    override fun parse(json: JsonObject): CredentialOffer =
        CredentialOffer(gson.fromJson(json, CredentialOfferEwcV2::class.java))

    private companion object {
        const val CONFIGURATION_IDS = "credential_configuration_ids"
    }
}
