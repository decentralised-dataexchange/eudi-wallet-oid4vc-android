package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.parser.legacy

import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.v1.IssuerWellKnownConfigurationV1
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.IssuerMetadataSpecVersion
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.parser.IssuerMetadataParser
import com.google.gson.Gson
import com.google.gson.JsonObject

/**
 * LEGACY -- pre-1.0 draft Credential Issuer metadata.
 *
 * Identified by `credentials_supported`, an **array** of credential objects rather than 1.0's
 * object keyed by configuration id. These documents also carry the singular `authorization_server`
 * in place of 1.0's `authorization_servers` array, and EBSI adds a `trust_framework` object that
 * appears in no version of the specification. All three are passed through untouched.
 *
 * This is the shape the EBSI conformance issuer publishes, so deleting it drops EBSI support.
 * Delete this file and its registry entry to drop draft support.
 */
class DraftIssuerMetadataParser(
    private val gson: Gson = Gson(),
) : IssuerMetadataParser {

    override val specVersion: IssuerMetadataSpecVersion = IssuerMetadataSpecVersion.Draft

    override fun supports(json: JsonObject): Boolean {
        val credentials = json.get(CREDENTIALS_SUPPORTED) ?: return false
        return !credentials.isJsonNull
    }

    override fun parse(json: JsonObject): IssuerWellKnownConfiguration =
        IssuerWellKnownConfiguration(gson.fromJson(json, IssuerWellKnownConfigurationV1::class.java))

    private companion object {
        const val CREDENTIALS_SUPPORTED = "credentials_supported"
    }
}
