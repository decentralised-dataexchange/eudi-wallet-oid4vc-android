package com.ewc.eudi_wallet_oidc_android.services.credentialRevocation

interface StatusListInterface {
    fun extractUniqueStatusUris(credentials: List<String?>): List<String>
    fun extractStatusDetails(credential: String): Pair<Int?, String?>?
}