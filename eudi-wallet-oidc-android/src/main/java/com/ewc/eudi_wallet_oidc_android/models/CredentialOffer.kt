package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class CredentialOffer(
    @SerializedName("credential_issuer") var credentialIssuer: String? = null,
    @SerializedName("credentials") var credentials: ArrayList<Any>? = null,
    @SerializedName("grants") var grants: Grants? = null
)

data class CredentialOfferV1(
    @SerializedName("credential_issuer") var credentialIssuer: String? = null,
    @SerializedName("credentials") var credentials: ArrayList<Credentials>? = null,
    @SerializedName("grants") var grants: Grants? = null
)

data class CredentialOfferV2(
    @SerializedName("credential_issuer") var credentialIssuer: String? = null,
    @SerializedName("credentials") var credentials: ArrayList<String>? = null,
    @SerializedName("grants") var grants: Grants? = null
)

data class Credentials(

    @SerializedName("format") var format: String? = null,
    @SerializedName("types") var types: ArrayList<String>? = null,
    @SerializedName("trust_framework") var trustFramework: TrustFramework? = null

)

data class Grants(

    @SerializedName("authorization_code") var authorizationCode: AuthorizationCode? = null,
    @SerializedName("urn:ietf:params:oauth:grant-type:pre-authorized_code") var preAuthorizationCode: PreAuthorizationCode? = null

)

data class AuthorizationCode(

    @SerializedName("issuer_state") var issuerState: String? = null

)

data class PreAuthorizationCode(

    @SerializedName("pre-authorized_code") var preAuthorizedCode: String? = null,
    @SerializedName("user_pin_required") var userPinRequired: Boolean? = null

)


data class TrustFramework(

    @SerializedName("name") var name: String? = null,
    @SerializedName("type") var type: String? = null,
    @SerializedName("uri") var uri: String? = null

)