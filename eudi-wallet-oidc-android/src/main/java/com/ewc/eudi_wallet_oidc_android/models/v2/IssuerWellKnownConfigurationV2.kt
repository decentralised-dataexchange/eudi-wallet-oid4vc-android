package com.ewc.eudi_wallet_oidc_android.models.v2

import com.ewc.eudi_wallet_oidc_android.models.CredentialDisplay
import com.ewc.eudi_wallet_oidc_android.models.Display
import com.ewc.eudi_wallet_oidc_android.models.Image
import com.ewc.eudi_wallet_oidc_android.models.TrustFramework

import com.google.gson.annotations.SerializedName

data class IssuerWellKnownConfigurationV2(
    @SerializedName("issuer") var issuer: String? = null,
    @SerializedName("credential_issuer") var credentialIssuer: String? = null,
    @SerializedName("authorization_server") var authorizationServer: String? = null,
    @SerializedName("authorization_servers") var authorizationServers: ArrayList<String>? = null,
    @SerializedName("credential_endpoint") var credentialEndpoint: String? = null,
    @SerializedName("deferred_credential_endpoint") var deferredCredentialEndpoint: String? = null,
    @SerializedName("display") var display: Any? = null,
    @SerializedName("credential_configurations_supported") var credentialConfigurationsSupported: Any? = null,
    @SerializedName("notification_endpoint") var notificationEndpoint: String? = null,
    @SerializedName("nonce_endpoint") var nonceEndpoint: String? = null
)
data class CredentialsSupportedV2(
    @SerializedName("format") var format: String? = null,
    @SerializedName("types") var types: ArrayList<String> = arrayListOf(),
    @SerializedName("trust_framework") var trustFramework: TrustFramework? = TrustFramework(),
    @SerializedName("display") var display: ArrayList<Display> = arrayListOf(),
    @SerializedName("cryptographic_suites_supported") var cryptographicSuitesSupported: ArrayList<String> = arrayListOf(),
)
data class CredentialDetailsV2(
    @SerializedName("format") val format: String? = null,
    @SerializedName("scope") val scope: String? = null,
    @SerializedName("cryptographic_binding_methods_supported") val cryptographicBindingMethodsSupported: List<String>? = null,
    @SerializedName("credential_signing_alg_values_supported") val credentialSigningAlgValuesSupported: List<String>? = null,
    @SerializedName("display") val display: List<CredentialDisplay>? = null,
    @SerializedName("doctype") val doctype: String? = null,
    @SerializedName("credential_definition") val  credentialDefinition: Any? = null,
    @SerializedName("vct") var vct: String? = null,
)