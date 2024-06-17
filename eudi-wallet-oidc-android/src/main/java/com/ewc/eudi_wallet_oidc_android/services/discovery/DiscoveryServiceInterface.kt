package com.ewc.eudi_wallet_oidc_android.services.discovery

import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.WrappedAuthConfigResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedIssuerConfigResponse

interface DiscoveryServiceInterface {
    suspend fun getIssuerConfig(credentialIssuerWellKnownURI:String?):WrappedIssuerConfigResponse?

    suspend fun getAuthConfig(authorisationServerWellKnownURI:String?): WrappedAuthConfigResponse?
}