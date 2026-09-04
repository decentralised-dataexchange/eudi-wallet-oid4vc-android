package com.ewc.eudi_wallet_oidc_android.models

import com.google.gson.annotations.SerializedName

/**
 * A failure, as far as it could be understood.
 *
 * [error] is a **legacy sentinel**, not the protocol's error code: it only ever holds `1`
 * ("the DID is invalid") or `-1` ("read [errorDescription]"), which is why an `Int` was enough.
 * OAuth error codes are strings — `invalid_grant`, `invalid_proof`, `use_dpop_nonce` — so they
 * could never fit here and were dropped on the floor. New code should branch on [errorCode] and
 * leave [error] to the callers that still switch on it.
 */
data class ErrorResponse(
    @SerializedName("error") var error: Int? = null,
    @SerializedName("error_description") var errorDescription: String? = null,

    /**
     * The OAuth 2.0 error code exactly as the server sent it, when it sent one.
     *
     * This is the only part of a failure a program can act on: RFC 6749 §5.2 and OpenID4VCI §6.3
     * define the codes, and a wallet needs them to tell "wrong transaction code" from "expired
     * offer" without matching on prose that changes per issuer and per language.
     */
    var errorCode: String? = null,

    /** RFC 6749 §5.2 `error_uri` — a page describing the error, when the server offers one. */
    var errorUri: String? = null,

    /** The HTTP status the failure arrived with, when a response carried it. */
    var httpStatus: Int? = null,

    /** The unparsed body, kept for diagnostics when none of the known shapes matched. */
    var raw: String? = null,
)

data class CredentialResponse(
    @SerializedName("format") var format: String? = null,
    @SerializedName("credential") var credential: String? = null,
    @SerializedName("credentials") var credentials: ArrayList<Credential>? = null,
    @SerializedName("acceptance_token") var acceptanceToken: String? = null,
    @SerializedName("transaction_id") var transactionId: String? = null,
    @SerializedName("isDeferred") var isDeferred: Boolean? = null,
    @SerializedName("isPinRequired") var isPinRequired: Boolean? = null,
    @SerializedName("issuerConfig") var issuerConfig: IssuerWellKnownConfiguration? = null,
    @SerializedName("authorizationConfig") var authorizationConfig: AuthorisationServerWellKnownConfiguration? = null,
    @SerializedName("credentialOffer") var credentialOffer: CredentialOffer? = null,
    @SerializedName("notification_id") var notificationId: String? = null,
    @SerializedName("interval") var interval: Int? = null
)

data class Credential(
    @SerializedName("credential") var credential: String? = null
)

data class WrappedCredentialResponse(
    var credentialResponse: CredentialResponse? = null,
    var errorResponse: ErrorResponse? = null,
)
