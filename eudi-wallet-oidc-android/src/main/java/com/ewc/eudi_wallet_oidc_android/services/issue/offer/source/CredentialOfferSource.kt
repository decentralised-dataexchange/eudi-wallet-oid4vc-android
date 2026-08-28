package com.ewc.eudi_wallet_oidc_android.services.issue.offer.source

import com.ewc.eudi_wallet_oidc_android.services.issue.offer.CredentialOfferPolicy

/**
 * One way an issuer can hand a credential offer to the wallet.
 *
 * OpenID4VCI 1.0 defines two transfer mechanisms -- the `credential_offer` parameter and the
 * `credential_offer_uri` parameter -- and both are implemented here. Sources are consulted in
 * registry order, so supporting a new mechanism is one class plus one registry entry.
 */
interface CredentialOfferSource {

    /** Human-readable name, used in error messages and logs. */
    val name: String

    /** True when [data] carries an offer this source can retrieve. */
    fun supports(data: String): Boolean

    /**
     * The raw credential offer JSON.
     *
     * @throws com.ewc.eudi_wallet_oidc_android.services.issue.offer.CredentialOfferException
     */
    suspend fun retrieve(data: String, policy: CredentialOfferPolicy): String
}
