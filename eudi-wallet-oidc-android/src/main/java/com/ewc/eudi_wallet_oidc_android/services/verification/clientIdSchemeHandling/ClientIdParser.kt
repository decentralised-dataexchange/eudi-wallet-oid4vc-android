package com.ewc.eudi_wallet_oidc_android.services.verification.clientIdSchemeHandling

import com.ewc.eudi_wallet_oidc_android.services.verification.ClientIdScheme

object ClientIdParser {
    /**
     * Parses the scheme part from a given client ID string.
     *
     * The scheme is the substring before the first colon (':') in the clientId.
     * For example, in "https://example.com:1234", the scheme is "https".
     *
     * @param clientId The full client ID string to parse.
     * @return The corresponding [ClientIdScheme] if the scheme is present and recognized;
     *         otherwise, null if the clientId does not contain a scheme.
     */
    fun getClientIdScheme(clientId: String): ClientIdScheme? {
        val scheme = clientId.substringBefore(":", missingDelimiterValue = "")
        return if (scheme.isNotEmpty()) {
            ClientIdScheme.fromScheme(scheme)
        } else {
            null
        }
    }

    /**
     * Extracts the scheme-specific identifier part from a given client ID string.
     *
     * The scheme-specific identifier is the substring after the first colon (':') in the clientId.
     * For example, in "https://example.com:1234", it returns "//example.com:1234".
     *
     * @param clientId The full client ID string to parse.
     * @return The scheme-specific identifier if present; otherwise, null.
     */
    fun getSchemeSpecificIdentifier(clientId: String): String? {
        val identifier = clientId.substringAfter(":", missingDelimiterValue = "")
        return if (identifier.isNotEmpty()) {
            identifier
        } else {
            null
        }
    }
}