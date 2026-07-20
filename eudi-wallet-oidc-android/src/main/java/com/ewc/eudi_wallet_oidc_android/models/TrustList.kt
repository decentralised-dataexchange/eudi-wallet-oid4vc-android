package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

/**
 * Payload models for the OWS Trust List backend (open lookup endpoint) used by
 * [com.ewc.eudi_wallet_oidc_android.services.trust.ServerTrustMechanismService].
 *
 * Endpoint: POST {baseUrl}/trust-list/lookup -> lookup by x5c / kid / did / jwksUri.
 */
/**
 * Lookup body: send the identifier the verifier/issuer is known by — the certificate chain
 * ([x5c], primary path), its key id ([kid]), its DID ([did]), or its JWKS URI ([jwksUri]). Exactly
 * one is populated.
 */
data class TrustListLookupRequest(
    @SerializedName("x5c")
    val x5c: List<String>? = null,

    @SerializedName("kid")
    val kid: String? = null,

    @SerializedName("did")
    val did: String? = null,

    @SerializedName("jwksUri")
    val jwksUri: String? = null
)

data class TrustListLookupResponse(
    @SerializedName("match")
    val match: Boolean = false,

    @SerializedName("entry")
    val entry: TrustListEntry? = null
)

data class TrustListEntry(
    @SerializedName("status")
    val status: String? = null,

    @SerializedName("provider")
    val provider: TrustListProvider? = null,

    @SerializedName("service")
    val service: TrustListService? = null,

    @SerializedName("certificateDetails")
    val certificateDetails: List<TrustListCertDetail>? = null,

    @SerializedName("matchedCertIndex")
    val matchedCertIndex: Int? = null
)

data class TrustListCertDetail(
    @SerializedName("subjectKeyIdentifier")
    val subjectKeyIdentifier: String? = null,

    @SerializedName("sha256Fingerprint")
    val sha256Fingerprint: String? = null
)

data class TrustListProvider(
    @SerializedName("tSPName")
    val tSPName: String? = null,

    @SerializedName("tSPTradeName")
    val tSPTradeName: String? = null,

    @SerializedName("streetAddress")
    val streetAddress: String? = null,

    @SerializedName("locality")
    val locality: String? = null,

    @SerializedName("postalCode")
    val postalCode: String? = null,

    @SerializedName("countryName")
    val countryName: String? = null,

    @SerializedName("electronicAddress")
    val electronicAddress: String? = null,

    @SerializedName("tSPInformationURI")
    val tSPInformationURI: String? = null
)

data class TrustListService(
    @SerializedName("serviceTypeIdentifier")
    val serviceTypeIdentifier: String? = null,

    @SerializedName("serviceStatus")
    val serviceStatus: String? = null,

    @SerializedName("statusStartingTime")
    val statusStartingTime: String? = null,

    @SerializedName("serviceName")
    val serviceName: String? = null,

    @SerializedName("digitalIdentity")
    val digitalIdentity: List<String>? = null
)
