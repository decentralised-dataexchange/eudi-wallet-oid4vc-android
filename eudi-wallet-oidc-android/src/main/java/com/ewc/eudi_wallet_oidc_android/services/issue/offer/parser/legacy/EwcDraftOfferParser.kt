package com.ewc.eudi_wallet_oidc_android.services.issue.offer.parser.legacy

import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.v1.CredentialOfferEwcV1
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.CredentialOfferSpecVersion
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.parser.CredentialOfferParser
import com.google.gson.Gson
import com.google.gson.JsonObject

/**
 * LEGACY -- pre-1.0 draft, EWC flavour: `credentials` is an array of **strings**, each naming a
 * credential type.
 *
 * Unlike the previous implementation this does not accept any object at all: a document with no
 * `credentials` array is rejected rather than becoming an empty offer. `{}` used to parse
 * "successfully" here and fail much later with no useful message.
 *
 * Delete this file and its registry entry to drop draft support.
 */
class EwcDraftOfferParser(
    private val gson: Gson = Gson(),
) : CredentialOfferParser {

    override val specVersion: CredentialOfferSpecVersion = CredentialOfferSpecVersion.Draft

    override fun supports(json: JsonObject): Boolean {
        val credentials = json.get(CREDENTIALS) ?: return false
        if (!credentials.isJsonArray) return false
        return credentials.asJsonArray.all { it.isJsonPrimitive && it.asJsonPrimitive.isString }
    }

    override fun parse(json: JsonObject): CredentialOffer =
        CredentialOffer(gson.fromJson(json, CredentialOfferEwcV1::class.java))

    private companion object {
        const val CREDENTIALS = "credentials"
    }
}
