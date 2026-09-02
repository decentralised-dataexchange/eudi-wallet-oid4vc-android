package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata

import java.net.URI

/**
 * Turns an issuer or authorization server identifier into the URLs its metadata might live at.
 *
 * OpenID4VCI 1.0 section 12.2.2 defines exactly one form: the well-known string is **inserted
 * between the host component and the path component**, so
 * `https://issuer.example.com/tenant` publishes at
 * `https://issuer.example.com/.well-known/openid-credential-issuer/tenant`. RFC 8414 section 3
 * says the same for authorization server metadata.
 *
 * The suffix form -- appending the well-known string to the end -- is **not** in either spec, but
 * a large share of deployed issuers serve only that, so it is kept as a fallback behind
 * [DiscoveryPolicy.allowSuffixWellKnownFallback].
 */
object WellKnownUrlBuilder {

    const val OPENID_CREDENTIAL_ISSUER = ".well-known/openid-credential-issuer"
    const val OAUTH_AUTHORIZATION_SERVER = ".well-known/oauth-authorization-server"
    const val OPENID_CONFIGURATION = ".well-known/openid-configuration"

    private val KNOWN_SUFFIXES = listOf(
        OPENID_CREDENTIAL_ISSUER,
        OAUTH_AUTHORIZATION_SERVER,
        OPENID_CONFIGURATION,
    )

    /**
     * The bare identifier behind [input], with any well-known segment and trailing slash removed.
     *
     * Callers pass a full well-known URL as often as a bare identifier -- the wallet builds
     * `"$issuer/.well-known/openid-credential-issuer"` before calling. Removing the segment with
     * its leading slash normalises both spec forms, because the segment sits in the middle of the
     * insertion form and at the end of the suffix form.
     *
     * @return null when [input] is blank.
     */
    fun identifier(input: String?): String? {
        var value = input?.trim().orEmpty()
        if (value.isEmpty()) return null
        for (suffix in KNOWN_SUFFIXES) {
            value = value.replace("/$suffix", "")
        }
        value = value.trimEnd('/')
        return value.takeIf { it.isNotEmpty() }
    }

    /** The scheme of [identifier], or null when it is not a parseable absolute URL. */
    fun scheme(identifier: String?): String? = try {
        URI(identifier).scheme
    } catch (e: Exception) {
        null
    }

    /**
     * The spec form: [wellKnown] inserted between the host and the path.
     *
     * @return null when [identifier] is not a parseable absolute URL.
     */
    fun insertionForm(identifier: String, wellKnown: String): String? = try {
        val uri = URI(identifier)
        val scheme = uri.scheme
        val authority = uri.authority
        if (scheme.isNullOrBlank() || authority.isNullOrBlank()) {
            null
        } else {
            val path = uri.path?.trim('/').orEmpty()
            if (path.isEmpty()) "$scheme://$authority/$wellKnown" else "$scheme://$authority/$wellKnown/$path"
        }
    } catch (e: Exception) {
        null
    }

    /** The non-spec fallback form: [wellKnown] appended to [identifier]. */
    fun suffixForm(identifier: String, wellKnown: String): String =
        "${identifier.trimEnd('/')}/$wellKnown"

    /**
     * The URLs to try for [wellKnown], spec form first.
     *
     * The two forms coincide when the identifier has no path, so the result is de-duplicated and
     * may hold a single entry.
     */
    fun candidates(identifier: String, wellKnown: String, policy: DiscoveryPolicy): List<String> {
        val urls = LinkedHashSet<String>()
        insertionForm(identifier, wellKnown)?.let { urls.add(it) }
        if (policy.allowSuffixWellKnownFallback) urls.add(suffixForm(identifier, wellKnown))
        return urls.toList()
    }
}
