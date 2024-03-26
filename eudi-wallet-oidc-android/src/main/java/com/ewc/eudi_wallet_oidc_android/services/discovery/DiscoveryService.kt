package com.ewc.eudi_wallet_oidc_android.services.discovery

import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.services.UriValidationFailed
import com.ewc.eudi_wallet_oidc_android.services.UrlUtils
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager

class DiscoveryService : DiscoveryServiceInterface {

    /**
     * To fetch the Issue configuration
     *
     * @param credentialIssuerWellKnownURI
     * @return IssuerWellKnownConfiguration
     */
    override suspend fun getIssuerConfig(credentialIssuerWellKnownURI: String?): IssuerWellKnownConfiguration? {
        try {
            UrlUtils.validateUri(credentialIssuerWellKnownURI)
            val response =
                ApiManager.api.getService()
                    ?.fetchIssuerConfig("$credentialIssuerWellKnownURI")
            return if (response?.isSuccessful == true) {
                response.body()
            } else {
                null
            }
        } catch (exc: UriValidationFailed) {
            return null
        }
    }

    /**
     * To fetch the authorisation server configuration
     *
     * @param authorisationServerWellKnownURI
     * @return AuthorisationServerWellKnownConfiguration
     */
    override suspend fun getAuthConfig(authorisationServerWellKnownURI: String?): AuthorisationServerWellKnownConfiguration? {
        try {
            UrlUtils.validateUri(authorisationServerWellKnownURI)

            val response =
                ApiManager.api.getService()
                    ?.fetchAuthConfig("$authorisationServerWellKnownURI")
            return if (response?.isSuccessful == true) {
                response.body()
            } else {
                null
            }
        } catch (exc: UriValidationFailed) {
            return null
        }
    }
}