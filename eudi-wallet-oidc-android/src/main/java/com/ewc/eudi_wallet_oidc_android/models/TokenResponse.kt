package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

data class TokenResponse(

    @SerializedName("access_token") var accessToken: String? = null,
    @SerializedName("token_type") var tokenType: String? = null,
    @SerializedName("expires_in") var expiresIn: Long? = null,
    @SerializedName("id_token") var idToken: String? = null,
    @SerializedName("c_nonce") var cNonce: String? = null,
    @SerializedName("c_nonce_expires_in") var cNonceExpiresIn: Long? = null,
    @SerializedName("error") var error: String? = null,
    @SerializedName("error_description") var errorDescription: String? = null,
    @SerializedName("refresh_token") var refreshToken: String? = null,
    @SerializedName("authorization_details") var authorizationDetails: List<AuthorizationDetail>? = null
)

data class WrappedTokenResponse(
    var tokenResponse: TokenResponse? = null,
    var errorResponse: ErrorResponse? = null,
    var legalPidAttestation: String? = null,
    var legalPidAttestationPoP: String? = null,
    var dpop: String? = null,

    /**
     * A nonce the authorization server supplied in a `DPoP-Nonce` header, on the success or on a
     * `use_dpop_nonce` challenge.
     *
     * RFC 9449 section 8.2: the client "MUST use the new nonce value supplied for the next token
     * request and for all subsequent token requests until the authorization server supplies a new
     * nonce". Carry it forward rather than discarding it.
     */
    var dpopNonce: String? = null,
)

data class AuthorizationDetail(
    @SerializedName("type") val type: String? = null,
    @SerializedName("credential_configuration_id") val credentialConfigurationId: String? = null,
    @SerializedName("credential_identifiers") val credentialIdentifiers: List<String>? = null
)