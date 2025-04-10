package com.ewc.eudi_wallet_oidc_android.services.credentialRevocation

interface CredentialRevocationServiceInterface {
    fun getRevokedCredentials(credentials: List<String?>, callback: (List<String>) -> Unit)
}