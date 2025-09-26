package com.ewc.eudi_wallet_oidc_android.models

import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.PublicKeyJwk
import com.google.gson.annotations.SerializedName

data class DIDDocument(
    @SerializedName("@context")
    val context: List<String>,

    @SerializedName("id")
    val id: String,

    @SerializedName("controller")
    val controller: List<String>,

    @SerializedName("verificationMethod")
    val verificationMethods: List<VerificationMethod>,

    @SerializedName("authentication")
    val authentication: List<String>,

    @SerializedName("assertionMethod")
    val assertionMethods: List<String>,

    @SerializedName("capabilityInvocation")
    val capabilityInvocations: List<String>
)

data class VerificationMethod(
    @SerializedName("id")
    val id: String,

    @SerializedName("type")
    val type: String,

    @SerializedName("controller")
    val controller: String,

    @SerializedName("publicKeyJwk")
    val publicKeyJwk: PublicKeyJwk ?= null,

    @SerializedName("publicKeyBase58")
    val publicKeyBase58: String? = null
)

data class PublicKeyJwk(
    @SerializedName("kty")
    val kty: String,

    @SerializedName("crv")
    val crv: String,

    @SerializedName("x")
    val x: String,

    @SerializedName("y")
    val y: String
)