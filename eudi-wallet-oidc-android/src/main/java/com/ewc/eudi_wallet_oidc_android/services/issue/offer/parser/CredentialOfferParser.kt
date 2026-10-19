package com.ewc.eudi_wallet_oidc_android.services.issue.offer.parser

import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.CredentialOfferSpecVersion
import com.google.gson.JsonObject

/**
 * Turns an offer document into the normalised [CredentialOffer].
 *
 * One implementation per spec revision. Parsers are tried in registry order with OpenID4VCI 1.0
 * first, so a draft parser only ever sees a document 1.0 has already declined.
 *
 * Implementations must be pure: [supports] decides on shape alone and neither method performs I/O.
 */
interface CredentialOfferParser {

    /** Which revision this parser implements. */
    val specVersion: CredentialOfferSpecVersion

    /** True when [json] is shaped like this revision's offer. */
    fun supports(json: JsonObject): Boolean

    /** Normalises [json]. Only called when [supports] returned true. */
    fun parse(json: JsonObject): CredentialOffer
}
