package com.ewc.eudi_wallet_oidc_android.services

import java.net.InetAddress
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
    fun isHostReachable(url: String?): Boolean {
        return try {
            // Extract the hostname from the URL
            val host = URL(url).host
            // Check if the host can be resolved
            InetAddress.getByName(host) != null
        } catch (e: Exception) {
            false
        }
    }
}