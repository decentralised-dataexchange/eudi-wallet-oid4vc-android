package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.parser

import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.v2.IssuerWellKnownConfigurationV2
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.IssuerMetadataSpecVersion
import com.google.gson.Gson
import com.google.gson.JsonObject

/**
 * OpenID4VCI 1.0 Credential Issuer metadata.
 *
 * Identified by `credential_configurations_supported`, which 1.0 defines as an object keyed by
 * configuration id. Drafts carried `credentials_supported` instead, so the two shapes never
 * collide and this parser can be tried first without risk.
 */
class OpenId4VciV1IssuerMetadataParser(
    private val gson: Gson = Gson(),
) : IssuerMetadataParser {

    override val specVersion: IssuerMetadataSpecVersion = IssuerMetadataSpecVersion.V1_0

    override fun supports(json: JsonObject): Boolean {
        val configurations = json.get(CREDENTIAL_CONFIGURATIONS_SUPPORTED) ?: return false
        return !configurations.isJsonNull
    }

    override fun parse(json: JsonObject): IssuerWellKnownConfiguration =
        IssuerWellKnownConfiguration(gson.fromJson(json, IssuerWellKnownConfigurationV2::class.java))

    private companion object {
        const val CREDENTIAL_CONFIGURATIONS_SUPPORTED = "credential_configurations_supported"
    }
}
