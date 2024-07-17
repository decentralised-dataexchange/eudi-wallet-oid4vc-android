package com.ewc.eudi_wallet_oidc_android.models

// Data class representing a response containing a list of JSON Web Keys (JWKs).
data class JwksResponse(val keys: List<JwkKey>)