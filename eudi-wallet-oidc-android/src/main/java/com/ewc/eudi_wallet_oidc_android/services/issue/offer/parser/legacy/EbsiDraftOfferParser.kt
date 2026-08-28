package com.ewc.eudi_wallet_oidc_android.services.issue.offer.parser.legacy

import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.v1.CredentialOfferEbsiV1
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.CredentialOfferSpecVersion
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.parser.CredentialOfferParser
import com.google.gson.Gson
import com.google.gson.JsonObject

/**
 * LEGACY -- pre-1.0 draft, EBSI flavour: `credentials` is an array of **objects** carrying
 * `format`, `types`, `doctype` and `trust_framework`.
 *
 * This is the only offer shape that conveys a format or an mdoc `doctype` in the offer itself, so
 * those fields are passed through untouched.
 *
 * Delete this file and its registry entry to drop draft support.
 */
class EbsiDraftOfferParser(
    private val gson: Gson = Gson(),
) : CredentialOfferParser {

    override val specVersion: CredentialOfferSpecVersion = CredentialOfferSpecVersion.Draft

    override fun supports(json: JsonObject): Boolean {
        val credentials = json.get(CREDENTIALS) ?: return false
        if (!credentials.isJsonArray) return false
        val array = credentials.asJsonArray
        // An empty array is ambiguous between the two draft flavours; let the EWC parser take it.
        return array.size() > 0 && array.all { it.isJsonObject }
    }

    override fun parse(json: JsonObject): CredentialOffer =
        CredentialOffer(gson.fromJson(json, CredentialOfferEbsiV1::class.java))

    private companion object {
        const val CREDENTIALS = "credentials"
    }
}
