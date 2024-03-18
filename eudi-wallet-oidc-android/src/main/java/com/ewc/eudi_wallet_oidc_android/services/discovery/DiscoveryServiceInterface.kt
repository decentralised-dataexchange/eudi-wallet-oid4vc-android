package com.ewc.eudi_wallet_oidc_android.services.discovery

import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration

interface DiscoveryServiceInterface {
    suspend fun getIssuerConfig(credentialIssuerWellKnownURI:String?):IssuerWellKnownConfiguration?

    suspend fun getAuthConfig(authorisationServerWellKnownURI:String?):AuthorisationServerWellKnownConfiguration?
}