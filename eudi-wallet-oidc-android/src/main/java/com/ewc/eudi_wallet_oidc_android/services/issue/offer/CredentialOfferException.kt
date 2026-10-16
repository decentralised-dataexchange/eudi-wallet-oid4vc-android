package com.ewc.eudi_wallet_oidc_android.services.issue.offer

/**
 * Why an offer could not be resolved.
 *
 * Every failure carries a description meant to be shown to a user, because
 * `WrappedCredentialOffer.errorResponse.errorDescription` is toasted verbatim by the wallet.
 */
sealed class CredentialOfferException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause) {

    /** The scanned data carried neither `credential_offer` nor `credential_offer_uri`. */
    class NoOffer : CredentialOfferException("This QR code does not contain a credential offer")

    /** Both transfer mechanisms present. The spec forbids this. */
    class AmbiguousOffer : CredentialOfferException(
        "The credential offer is invalid: it uses both credential_offer and credential_offer_uri"
    )

    /** `credential_offer_uri` used a scheme the policy does not allow. */
    class UnsupportedScheme(val scheme: String?) :
        CredentialOfferException("The credential offer link uses an unsupported scheme: $scheme")

    /** The `credential_offer_uri` fetch failed. */
    class FetchFailed(val httpStatus: Int?, detail: String?) : CredentialOfferException(
        detail?.takeIf { it.isNotBlank() }
            ?: "The credential offer could not be downloaded${httpStatus?.let { " (HTTP $it)" }.orEmpty()}"
    )

    /** The issuer returned something that is not JSON. */
    class NotJson(val contentType: String?) :
        CredentialOfferException("The credential offer was not in the expected format")

    /**
     * The offer was delivered as a JWT. OpenID4VCI 1.0: "The Credential Offer cannot be signed and
     * MUST NOT use application/jwt".
     */
    class SignedOfferRejected :
        CredentialOfferException("Signed credential offers are not supported")

    /** The document exceeded [CredentialOfferPolicy.maxOfferBytes]. */
    class TooLarge(val bytes: Long) :
        CredentialOfferException("The credential offer is too large to process")

    /** The document was not parseable JSON, or matched no known offer shape. */
    class Malformed(detail: String) : CredentialOfferException(detail)

    /** Parsed, but does not satisfy the spec. */
    class Invalid(detail: String) : CredentialOfferException(detail)
}
