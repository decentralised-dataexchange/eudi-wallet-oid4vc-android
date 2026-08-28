package com.ewc.eudi_wallet_oidc_android.services.issue.offer

import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import java.net.URI

/**
 * Spec conformance for a parsed offer, in one place.
 *
 * Validation is deliberately separate from parsing: a parser decides *which revision* a document
 * is, this decides whether the document is *usable*. Rules are OpenID4VCI 1.0 section 4.
 */
class CredentialOfferValidator {

    /**
     * @return the offer, normalised where the spec defines a default.
     * @throws CredentialOfferException.Invalid
     */
    fun validate(offer: CredentialOffer, specVersion: CredentialOfferSpecVersion): CredentialOffer {
        // credential_issuer: REQUIRED.
        val issuer = offer.credentialIssuer?.trim()
        if (issuer.isNullOrEmpty()) {
            throw CredentialOfferException.Invalid("The credential offer does not name an issuer")
        }
        if (!isAbsoluteUrl(issuer)) {
            throw CredentialOfferException.Invalid("The credential offer names an invalid issuer: $issuer")
        }

        // credential_configuration_ids: REQUIRED, non-empty, unique.
        val credentials = offer.credentials
        if (credentials.isNullOrEmpty()) {
            throw CredentialOfferException.Invalid("The credential offer does not name any credentials")
        }
        val identifiers = credentials.mapNotNull { credential ->
            when (specVersion) {
                CredentialOfferSpecVersion.V1_0 -> credential.types?.firstOrNull()
                CredentialOfferSpecVersion.Draft -> credential.types?.lastOrNull()
            }?.takeIf { it.isNotBlank() }
        }
        if (identifiers.isEmpty()) {
            throw CredentialOfferException.Invalid("The credential offer does not name any credentials")
        }
        if (specVersion == CredentialOfferSpecVersion.V1_0 &&
            identifiers.size != identifiers.toSet().size
        ) {
            // Duplicates would otherwise be requested twice.
            throw CredentialOfferException.Invalid(
                "The credential offer names the same credential more than once"
            )
        }

        // A pre-authorized grant MUST carry a code.
        offer.grants?.preAuthorizationCode?.let { grant ->
            if (grant.preAuthorizedCode.isNullOrBlank()) {
                throw CredentialOfferException.Invalid(
                    "The credential offer is missing its pre-authorized code"
                )
            }
            grant.transactionCode = grant.transactionCode?.let(::normalizeTransactionCode)
        }

        offer.credentialIssuer = issuer
        return offer
    }

    /**
     * `input_mode` defaults to `numeric`; an unrecognised value falls back to it rather than
     * failing the offer. `description` MUST NOT exceed 300 characters, and is issuer-controlled
     * text rendered directly in the PIN screen, so it is truncated rather than trusted.
     */
    private fun normalizeTransactionCode(
        txCode: com.ewc.eudi_wallet_oidc_android.models.TxCode
    ): com.ewc.eudi_wallet_oidc_android.models.TxCode = txCode.apply {
        inputMode = when (inputMode?.lowercase()) {
            INPUT_MODE_TEXT -> INPUT_MODE_TEXT
            else -> INPUT_MODE_NUMERIC
        }
        description = description?.takeIf { it.isNotBlank() }?.let {
            if (it.length > MAX_DESCRIPTION_LENGTH) it.take(MAX_DESCRIPTION_LENGTH) else it
        }
        length = length?.takeIf { it > 0 }
    }

    private fun isAbsoluteUrl(value: String): Boolean = try {
        val uri = URI(value)
        uri.isAbsolute && !uri.host.isNullOrBlank()
    } catch (e: Exception) {
        false
    }

    private companion object {
        const val INPUT_MODE_NUMERIC = "numeric"
        const val INPUT_MODE_TEXT = "text"
        const val MAX_DESCRIPTION_LENGTH = 300
    }
}
