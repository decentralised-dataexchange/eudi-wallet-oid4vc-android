package com.ewc.eudi_wallet_oidc_android.services.issue.authorization

import java.net.URLDecoder
import java.net.URLEncoder

/**
 * Reading and building authorization URLs.
 *
 * Deliberately built on `java.net` rather than `android.net.Uri`, for the same reason the offer
 * package is: `android.net.Uri` is stubbed in JVM unit tests and returns null from every method, so
 * anything using it can only be tested on a device. The whole authorization package stays testable
 * as plain unit tests.
 *
 * Decoding matches `Uri.getQueryParameter`: percent-decoded, and `+` means space.
 */
internal object AuthorizationUri {

    /** First occurrence of [name] in the query string, decoded, or null. */
    fun queryParameter(url: String?, name: String): String? {
        if (url.isNullOrEmpty()) return null
        val query = url.substringBefore('#').substringAfter('?', "")
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

    /** [base] with [parameters] appended, skipping blank values. */
    fun appendQueryParameters(base: String, parameters: Map<String, String?>): String {
        val encoded = parameters
            .filterValues { !it.isNullOrEmpty() }
            .map { (name, value) -> "${encode(name)}=${encode(value!!)}" }
        if (encoded.isEmpty()) return base

        val separator = if (base.contains('?')) "&" else "?"
        return base + separator + encoded.joinToString("&")
    }

    private fun decode(value: String): String = try {
        URLDecoder.decode(value, "UTF-8")
    } catch (e: IllegalArgumentException) {
        // Malformed percent-escapes turn up in real redirects; keep the raw value rather than
        // discarding an otherwise usable response.
        value
    }

    private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8")
}
