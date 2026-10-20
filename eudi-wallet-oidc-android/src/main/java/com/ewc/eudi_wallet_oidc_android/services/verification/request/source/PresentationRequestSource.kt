package com.ewc.eudi_wallet_oidc_android.services.verification.request.source

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy

/**
 * One way a verifier can hand an authorization request to the wallet.
 *
 * OpenID4VP 1.0 carries the parameters in the request URI itself, in a `request` object by value
 * (RFC 9101 section 5.1) or behind a `request_uri` (RFC 9101 section 5.2 and OpenID4VP section
 * 5.10). Sources are consulted in registry order, so a new mechanism is one class plus one
 * registry entry.
 */
interface PresentationRequestSource {

    /** Short name, used in logs and in [com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestOutcome.Resolved.source]. */
    val name: String

    /** True when [data] carries a request this source can retrieve. */
    fun supports(data: String): Boolean

    /**
     * The request parameters, parsed but not yet validated or dereferenced.
     *
     * @throws com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestException
     */
    suspend fun retrieve(data: String, policy: PresentationRequestPolicy): PresentationRequest
}
