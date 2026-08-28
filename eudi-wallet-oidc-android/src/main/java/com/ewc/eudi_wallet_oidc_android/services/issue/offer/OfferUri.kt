package com.ewc.eudi_wallet_oidc_android.services.issue.offer

import java.net.URLDecoder

/**
 * Minimal query-string handling for offer links.
 *
 * Deliberately built on java.net rather than android.net.Uri so the whole offer package is
 * testable as plain JVM unit tests. Decoding matches `Uri.getQueryParameter`: percent-decoded,
 * and `+` means space.
 */
internal object OfferUri {

    /** First occurrence of [name] in the query string, decoded, or null. */
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

    fun hasQueryParam(data: String?, name: String): Boolean = queryParam(data, name) != null

    /** Scheme of [data], lowercased, or null when it has none. */
    fun scheme(data: String?): String? {
        if (data.isNullOrBlank()) return null
        val separator = data.indexOf(':')
        if (separator <= 0) return null
        val scheme = data.substring(0, separator)
        // A scheme is ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) -- RFC 3986.
        if (!scheme.first().isLetter()) return null
        if (!scheme.all { it.isLetterOrDigit() || it == '+' || it == '-' || it == '.' }) return null
        return scheme.lowercase()
    }

    private fun decode(value: String): String = try {
        URLDecoder.decode(value, "UTF-8")
    } catch (e: IllegalArgumentException) {
        // Malformed percent-escapes are common in issuer links; keep the raw value.
        value
    }
}
