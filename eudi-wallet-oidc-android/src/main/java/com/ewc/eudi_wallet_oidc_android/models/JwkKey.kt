package com.ewc.eudi_wallet_oidc_android.models

// Data class representing a JSON Web Key (JWK).
data class JwkKey(
    val kty: String,
    val kid: String,
    val crv: String,
    val x: String,
    val y: String,
    val use: String
)