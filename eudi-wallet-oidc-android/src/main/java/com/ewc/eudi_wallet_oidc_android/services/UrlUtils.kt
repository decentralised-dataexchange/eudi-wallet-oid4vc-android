package com.ewc.eudi_wallet_oidc_android.services

import java.net.URL

class UriValidationFailed(s: String) : Exception()

object UrlUtils {

    /**
     * Validate uri
     *
     * @param uri
     */
    fun validateUri(uri: String?) {
        if (uri.isNullOrBlank() || !UrlUtils.isValidUrl(uri?:"")) {
            throw UriValidationFailed("URI validation failed")
        }
    }

    fun isValidUrl(url: String): Boolean {
        return try {
            URL(url)
            true
        } catch (e: Exception) {
            false
        }
    }
}