package com.ewc.eudi_wallet_oidc_android.services.discovery

import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager

class DiscoveryService : DiscoveryServiceInterface {

    /**
     * To fetch the Issue configuration
     * @param credentialIssuerWellKnownURI
     * 
     * @return IssuerWellKnownConfiguration
     */
    override suspend fun getIssuerConfig(credentialIssuerWellKnownURI: String?): IssuerWellKnownConfiguration? {
        if (credentialIssuerWellKnownURI.isNullOrBlank())
            return null

        val response =
            ApiManager.api.getService()?.fetchIssuerConfig("$credentialIssuerWellKnownURI/.well-known/openid-credential-issuer")
        return if (response?.isSuccessful == true) {
            response.body()
        } else {
            null
        }
    }

    /**
     * To fetch the authorisation server configuration
     * @param authorisationServerWellKnownURI
     *
     * @return AuthorisationServerWellKnownConfiguration
     */
    override suspend fun getAuthConfig(authorisationServerWellKnownURI: String?): AuthorisationServerWellKnownConfiguration? {
        if (authorisationServerWellKnownURI.isNullOrBlank())
            return null

        val response =
            ApiManager.api.getService()?.fetchAuthConfig("$authorisationServerWellKnownURI/.well-known/openid-configuration")
        return if (response?.isSuccessful == true) {
            response.body()
        } else {
            null
        }
    }
}