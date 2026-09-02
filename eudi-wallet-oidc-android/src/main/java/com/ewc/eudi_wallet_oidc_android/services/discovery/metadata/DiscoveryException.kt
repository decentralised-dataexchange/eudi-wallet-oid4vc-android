package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata

/**
 * Why metadata could not be discovered.
 *
 * Every failure carries a description meant to be shown to a user, because the wallet toasts
 * `errorResponse.errorDescription` verbatim.
 */
sealed class DiscoveryException(
    message: String,
    /** HTTP status, when the failure came from a response. */
    val httpStatus: Int? = null,
    cause: Throwable? = null,
) : Exception(message, cause) {

    /** No usable issuer or authorization server identifier was supplied. */
    class NoIdentifier : DiscoveryException("No issuer address was supplied")

    /** The identifier used a scheme the policy does not allow. */
    class UnsupportedScheme(val scheme: String?) :
        DiscoveryException("The issuer address uses an unsupported scheme: $scheme")

    /** The identifier was not a usable absolute URL. */
    class InvalidIdentifier(identifier: String?) :
        DiscoveryException("The issuer address is not valid: $identifier")

    /** The metadata request failed. */
    class FetchFailed(status: Int?, detail: String?) : DiscoveryException(
        detail?.takeIf { it.isNotBlank() }
            ?: "The issuer configuration could not be downloaded${status?.let { " (HTTP $it)" }.orEmpty()}",
        httpStatus = status,
    )

    /** The response was not the expected media type. */
    class NotJson(val contentType: String?) :
        DiscoveryException("The issuer configuration was not in the expected format")

    /** The document exceeded [DiscoveryPolicy.maxMetadataBytes]. */
    class TooLarge(val bytes: Long) :
        DiscoveryException("The issuer configuration is too large to process")

    /**
     * Signed metadata was returned but could not be trusted.
     *
     * OpenID4VCI 1.0 section 12.2.3: "When requesting signed metadata, the Wallet MUST establish
     * trust in the signer of the metadata. Otherwise, the Wallet MUST reject the signed metadata."
     */
    class SignedMetadataRejected(detail: String) : DiscoveryException(detail)

    /** Not parseable JSON, or matched no known metadata shape. */
    class Malformed(detail: String) : DiscoveryException(detail)

    /** Parsed, but does not satisfy the spec. */
    class Invalid(detail: String) : DiscoveryException(detail)
}

/**
 * Which of two failures to report when several well-known URLs were tried.
 *
 * A failure that got as far as reading a document says more than one that never found a document,
 * and a definite HTTP error says more than a 404 -- a 404 usually just means "this issuer uses the
 * other URL form". Ties keep the earlier failure, so the spec URL's complaint wins over the
 * fallback's.
 *
 * The old implementation kept the *last* failure instead, so a 403 on the URL an issuer actually
 * uses was reported as a 404 on whichever URL happened to be tried last.
 */
internal fun DiscoveryException?.orMoreInformativeThan(other: DiscoveryException): DiscoveryException {
    if (this == null) return other
    return if (other.informativeness() > this.informativeness()) other else this
}

private fun DiscoveryException.informativeness(): Int = when (this) {
    is DiscoveryException.FetchFailed -> if (httpStatus == HTTP_NOT_FOUND) 1 else 2
    else -> 3
}

private const val HTTP_NOT_FOUND = 404
