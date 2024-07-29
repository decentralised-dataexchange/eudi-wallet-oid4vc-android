package com.ewc.eudi_wallet_oidc_android.services.discovery

import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.WrappedAuthConfigResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedIssuerConfigResponse
import com.ewc.eudi_wallet_oidc_android.services.UriValidationFailed
import com.ewc.eudi_wallet_oidc_android.services.UrlUtils
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager

class DiscoveryService : DiscoveryServiceInterface {

    /**
     * To fetch the Issue configuration
     *
     * @param credentialIssuerWellKnownURI
     * @return WrappedIssuerConfigResponse
     */
    override suspend fun getIssuerConfig(credentialIssuerWellKnownURI: String?): WrappedIssuerConfigResponse {
        try {
            UrlUtils.validateUri(credentialIssuerWellKnownURI)
            val response =
                ApiManager.api.getService()
                    ?.fetchIssuerConfig("$credentialIssuerWellKnownURI")
            return if (response?.isSuccessful == true) {
                WrappedIssuerConfigResponse(issuerConfig = response.body(), errorResponse = null)
            } else {
                WrappedIssuerConfigResponse(issuerConfig = null, errorResponse = ErrorResponse(error = response?.code(), errorDescription = response?.message()))
            }
        } catch (exc: UriValidationFailed) {
            return WrappedIssuerConfigResponse(issuerConfig = null, errorResponse = ErrorResponse(error = null, errorDescription = "URI validation failed"))
        }
    }

    /**
     * To fetch the authorization server configuration
     *
     * @param authorisationServerWellKnownURI
     * @return WrappedAuthConfigResponse
     */
    override suspend fun getAuthConfig(authorisationServerWellKnownURI: String?): WrappedAuthConfigResponse {
        try {
            UrlUtils.validateUri(authorisationServerWellKnownURI)

            val response =
                ApiManager.api.getService()
                    ?.fetchAuthConfig("$authorisationServerWellKnownURI")
            return if (response?.isSuccessful == true) {
                WrappedAuthConfigResponse(authConfig = response.body(), errorResponse = null)
            } else {
                WrappedAuthConfigResponse(authConfig = null, errorResponse = ErrorResponse(error = response?.code(), errorDescription = response?.message()))
            }
        } catch (exc: UriValidationFailed) {
            return WrappedAuthConfigResponse(authConfig = null, errorResponse = ErrorResponse(error = null, errorDescription = "URI validation failed"))
        }
    }
}