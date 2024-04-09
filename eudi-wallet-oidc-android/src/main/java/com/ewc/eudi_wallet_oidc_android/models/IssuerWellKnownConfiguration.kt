package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class IssuerWellKnownConfiguration(
    @SerializedName("issuer") var issuer: String? = null,
    @SerializedName("credential_issuer") var credentialIssuer: String? = null,
    @SerializedName("authorization_server") var authorizationServer: String? = null,
    @SerializedName("authorization_servers") var authorizationServers: ArrayList<String>? = null,
    @SerializedName("credential_endpoint") var credentialEndpoint: String? = null,
    @SerializedName("deferred_credential_endpoint") var deferredCredentialEndpoint: String? = null,
    @SerializedName("display") var display: Any? = null,
    @SerializedName("credentials_supported") var credentialsSupported: Any? = null
)

data class CredentialsSupported(
    @SerializedName("format") var format: String? = null,
    @SerializedName("types") var types: ArrayList<String> = arrayListOf(),
    @SerializedName("trust_framework") var trustFramework: TrustFramework? = TrustFramework(),
    @SerializedName("display") var display: ArrayList<Display> = arrayListOf()
)

data class Display(
    @SerializedName("name") var name: String? = null,
    @SerializedName("location") var location: String? = null,
    @SerializedName("locale") var locale: String? = null,
    @SerializedName("cover") var cover: Image? = Image(),
    @SerializedName("logo") var logo: Image? = Image(),
    @SerializedName("description") var description: String? = null
)

data class Image(
    @SerializedName("uri") var uri: String? = null,
    @SerializedName("url") var url: String? = null,
    @SerializedName("alt_text") var altText: String? = null
)