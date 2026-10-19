package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.parser

import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.IssuerMetadataSpecVersion
import com.google.gson.JsonObject

/**
 * Turns a Credential Issuer metadata document into the normalised [IssuerWellKnownConfiguration].
 *
 * One implementation per spec revision, selected by document shape rather than by any version
 * field on the wire. Parsers are tried in registry order with OpenID4VCI 1.0 first, so a draft
 * parser only ever sees a document 1.0 has already declined.
 *
 * Implementations must be pure: [supports] decides on shape alone and neither method performs I/O.
 */
interface IssuerMetadataParser {

    /** Which revision this parser implements. */
    val specVersion: IssuerMetadataSpecVersion

    /** True when [json] is shaped like this revision's metadata. */
    fun supports(json: JsonObject): Boolean

    /** Normalises [json]. Only called when [supports] returned true. */
    fun parse(json: JsonObject): IssuerWellKnownConfiguration
}
