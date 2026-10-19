package com.ewc.eudi_wallet_oidc_android.services.issue.offer.source

import com.ewc.eudi_wallet_oidc_android.services.issue.offer.CredentialOfferException
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.CredentialOfferPolicy
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.OfferUri

/**
 * The offer travels inside the link itself, as `?credential_offer=<url-encoded JSON>`.
 *
 * OpenID4VCI 1.0 section 4.1.
 */
class InlineCredentialOfferSource : CredentialOfferSource {

    override val name: String = "credential_offer"

    override fun supports(data: String): Boolean =
        !OfferUri.queryParam(data, PARAM).isNullOrBlank()

    override suspend fun retrieve(data: String, policy: CredentialOfferPolicy): String {
        val offer = OfferUri.queryParam(data, PARAM)
        if (offer.isNullOrBlank()) throw CredentialOfferException.NoOffer()

        if (offer.length > policy.maxOfferBytes) {
            throw CredentialOfferException.TooLarge(offer.length.toLong())
        }
        return offer
    }

    private companion object {
        const val PARAM = "credential_offer"
    }
}
