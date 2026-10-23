package com.ewc.eudi_wallet_oidc_android.services.verification.request

import java.net.URLDecoder

/**
 * Minimal query string handling for authorization request links.
 *
 * Built on java.net rather than android.net.Uri so the whole request package runs as plain JVM
 * unit tests. Decoding matches `Uri.getQueryParameter`: percent-decoded, and `+` means space.
 */
internal object AuthorizationRequestUri {

    /** First occurrence of [name] in the query string, decoded, or null when absent. */
    fun queryParam(data: String?, name: String): String? {
        if (data.isNullOrEmpty()) return null

        val query = data.substringBefore('#').substringAfter('?', "")
        if (query.isEmpty()) return null

        query.split('&').forEach { pair ->
            if (pair.isEmpty()) return@forEach
            val separator = pair.indexOf('=')
            val rawKey = if (separator < 0) pair else pair.substring(0, separator)
            if (decode(rawKey) != name) return@forEach
            return if (separator < 0) "" else decode(pair.substring(separator + 1))
        }
        return null
    }

    /** True when [name] appears in the query string, even with an empty value. */
    fun hasQueryParam(data: String?, name: String): Boolean = queryParam(data, name) != null

    /** True when [name] appears with a value that is not blank. */
    fun hasValue(data: String?, name: String): Boolean = !queryParam(data, name).isNullOrBlank()

    private fun decode(value: String): String = try {
        URLDecoder.decode(value, "UTF-8")
    } catch (e: IllegalArgumentException) {
        // Malformed percent escapes happen in hand-built links; keep the raw value.
        value
    }
}
