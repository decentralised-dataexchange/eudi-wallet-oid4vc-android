package com.ewc.eudi_wallet_oidc_android.services.discovery

import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.WrappedAuthConfigResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedIssuerConfigResponse
import com.ewc.eudi_wallet_oidc_android.models.v1.IssuerWellKnownConfigurationV1
import com.ewc.eudi_wallet_oidc_android.models.v2.IssuerWellKnownConfigurationV2
import com.ewc.eudi_wallet_oidc_android.services.UriValidationFailed
import com.ewc.eudi_wallet_oidc_android.services.UrlUtils
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils
import com.google.gson.Gson
import java.net.URI

class DiscoveryService : DiscoveryServiceInterface {

    /**
     * Helper to construct RFC 8414 Section 3 compatible URLs when paths are present.
     * Inserts the wellKnownSuffix immediately after the host/port.
     */
    private fun buildRfc8414Url(inputUri: String?, wellKnownSuffix: String): String? {
        if (inputUri == null) return null
        return try {
            val uri = URI(inputUri)
            val scheme = uri.scheme ?: "https"
            val authority = uri.authority // includes host and port if present
            var path = uri.path ?: ""

            if (path.startsWith("/")) {
                path = path.substring(1)
            }

            if (path.isEmpty()) {
                "$scheme://$authority/$wellKnownSuffix"
            } else {
                "$scheme://$authority/$wellKnownSuffix/$path"
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * To fetch the Issue configuration
     */
    override suspend fun getIssuerConfig(credentialIssuerWellKnownURI: String?): WrappedIssuerConfigResponse? {
        val baseIssuer = credentialIssuerWellKnownURI?.replace("/.well-known/openid-credential-issuer", "")
            ?.let { removeTrailingSlash(it) } ?: return null

        // Primary strategy: Current suffix-style URL
        val primaryUrl = "$baseIssuer/.well-known/openid-credential-issuer"

        // Execute primary strategy
        val primaryResult = executeIssuerFetch(primaryUrl)
        if (primaryResult?.issuerConfig != null) {
            return primaryResult
        }

        // Fallback strategy: RFC 8414 Section 3 transformation
        val fallbackUrl = buildRfc8414Url(baseIssuer, ".well-known/openid-credential-issuer")
        if (!fallbackUrl.isNullOrEmpty() && fallbackUrl != primaryUrl) {
            val fallbackResult = executeIssuerFetch(fallbackUrl)
            if (fallbackResult?.issuerConfig != null) {
                return fallbackResult
            }
        }

        // Return the original primary result (with errors) if both failed
        return primaryResult
    }

    private suspend fun executeIssuerFetch(url: String): WrappedIssuerConfigResponse? {
        try {
            UrlUtils.validateUri(url)
            var finalResponse: WrappedIssuerConfigResponse? = null

            val result = SafeApiCall.safeApiCallResponse {
                ApiManager.api.getService()?.fetchIssuerConfig(url)
            }

            result.onSuccess { response ->
                finalResponse = if (response.isSuccessful) {
                    parseIssuerConfigurationResponse(issuerConfigResponseJson = response.body()?.string())
                } else {
                    WrappedIssuerConfigResponse(
                        issuerConfig = null,
                        errorResponse = ErrorResponse(error = response.code(), errorDescription = response.message())
                    )
                }
            }.onFailure { e ->
                val message = when (e) {
                    is javax.net.ssl.SSLHandshakeException -> "Unable to establish a secure connection."
                    else -> e.message.toString()
                }
                finalResponse = WrappedIssuerConfigResponse(
                    issuerConfig = null,
                    errorResponse = ErrorResponse(errorDescription = message)
                )
            }
            return finalResponse
        } catch (exc: UriValidationFailed) {
            return WrappedIssuerConfigResponse(issuerConfig = null, errorResponse = ErrorResponse(error = null, errorDescription = "URI validation failed"))
        }
    }

    private fun removeTrailingSlash(input: String?): String? {
        return if (input?.endsWith("/") == true) input.dropLast(1) else input
    }

    private fun parseIssuerConfigurationResponse(issuerConfigResponseJson: String?): WrappedIssuerConfigResponse? {
        val jsonToParse = if (JwtUtils.isValidJWT(issuerConfigResponseJson)) {
            try { JwtUtils.parseJWTForPayload(issuerConfigResponseJson) } catch (e: Exception) { issuerConfigResponseJson }
        } else {
            issuerConfigResponseJson
        }
        val gson = Gson()
        val issuerWellKnownConfigurationV2Response = try {
            gson.fromJson(jsonToParse, IssuerWellKnownConfigurationV2::class.java)
        } catch (e: Exception) { null }

        return if (issuerWellKnownConfigurationV2Response?.credentialConfigurationsSupported == null) {
            val issuerWellKnownConfigurationV1Response = try {
                gson.fromJson(jsonToParse, IssuerWellKnownConfigurationV1::class.java)
            } catch (e: Exception) { null }
            if (issuerWellKnownConfigurationV1Response?.credentialsSupported == null) {
                null
            } else {
                WrappedIssuerConfigResponse(
                    issuerConfig = IssuerWellKnownConfiguration(issuerWellKnownConfigurationV1 = issuerWellKnownConfigurationV1Response),
                    errorResponse = null
                )
            }
        } else {
            WrappedIssuerConfigResponse(
                issuerConfig = IssuerWellKnownConfiguration(issuerWellKnownConfigurationV2 = issuerWellKnownConfigurationV2Response),
                errorResponse = null
            )
        }
    }

    /**
     * To fetch the authorization server configuration
     */
    override suspend fun getAuthConfig(authorisationServerWellKnownURI: String?): WrappedAuthConfigResponse {
        val baseAuthServer = authorisationServerWellKnownURI?.replace("/.well-known/oauth-authorization-server", "")
            ?.replace("/.well-known/openid-configuration", "")
            ?.let { removeTrailingSlash(it) }

        // Core array of URLs we want to try step-by-step
        val urlsToTry = mutableListOf<String>()

        baseAuthServer?.let { base ->
            // 1. Current default
            urlsToTry.add("$base/.well-known/oauth-authorization-server")
            // 2. OpenID Connect alternative default
            urlsToTry.add("$base/.well-known/openid-configuration")

            // 3. RFC 8414 variations (if there is a path component)
            buildRfc8414Url(base, ".well-known/oauth-authorization-server")?.let {
                if (!urlsToTry.contains(it)) urlsToTry.add(it)
            }
            buildRfc8414Url(base, ".well-known/openid-configuration")?.let {
                if (!urlsToTry.contains(it)) urlsToTry.add(it)
            }
        }

        var lastErrorResponse: ErrorResponse? = null

        for (url in urlsToTry) {
            try {
                UrlUtils.validateUri(url)
                val result = SafeApiCall.safeApiCallResponse {
                    ApiManager.api.getService()?.fetchAuthConfig(url)
                }

                var successResponse: WrappedAuthConfigResponse? = null

                result.onSuccess { response ->
                    if (response.isSuccessful) {
                        successResponse = WrappedAuthConfigResponse(
                            authConfig = parseAuthConfigJson(response.body()?.string()),
                            errorResponse = null
                        )
                    } else {
                        lastErrorResponse = ErrorResponse(error = response.code(), errorDescription = response.message())
                    }
                }.onFailure { e ->
                    lastErrorResponse = ErrorResponse(errorDescription = e.message)
                }

                // If this specific URL attempt resolved successfully, return it early!
                if (successResponse?.authConfig != null) {
                    return successResponse!!
                }

            } catch (exc: UriValidationFailed) {
                lastErrorResponse = ErrorResponse(error = null, errorDescription = "URI validation failed for $url")
            }
        }

        return WrappedAuthConfigResponse(
            authConfig = null,
            errorResponse = lastErrorResponse ?: ErrorResponse(errorDescription = "Unexpected error during discovery processes")
        )
    }

    private fun parseAuthConfigJson(jsonOrJwt: String?): AuthorisationServerWellKnownConfiguration? {
        val jsonToParse = if (JwtUtils.isValidJWT(jsonOrJwt)) {
            try { JwtUtils.parseJWTForPayload(jsonOrJwt) } catch (e: Exception) { jsonOrJwt }
        } else {
            jsonOrJwt
        }
        return try {
            Gson().fromJson(jsonToParse, AuthorisationServerWellKnownConfiguration::class.java)
        } catch (e: Exception) {
            null
        }
    }
}