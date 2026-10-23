package com.ewc.eudi_wallet_oidc_android.services.verification.response

import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse

/** What submitting a presentation produced. */
sealed class PresentationOutcome {

    /**
     * The verifier accepted the response.
     *
     * @param redirectUri OpenID4VP 1.0 section 8.2: "When this parameter is present the Wallet
     *   MUST redirect the user agent to this URI." Null when the verifier sent none, in which case
     *   "the Wallet is not required to perform any further steps".
     * @param location the `Location` of a 302 answer, which some verifiers send instead of the
     *   JSON body. Not in 1.0; kept for them.
     * @param authorizationCode the `code` an issuer's interactive authorization endpoint returns
     *   once the presentation it asked for is accepted; the wallet exchanges it at the token
     *   endpoint to continue issuance.
     */
    data class Accepted(
        val redirectUri: String? = null,
        val location: String? = null,
        val authorizationCode: String? = null,
    ) : PresentationOutcome()

    /**
     * The response is ready but the host delivers it: the Digital Credentials API modes, where
     * the platform carries [parameters] back to the verifier.
     */
    data class Delivered(val parameters: Map<String, String>) : PresentationOutcome()

    /** Nothing was sent, or the verifier refused what was sent. */
    data class Refused(val error: ErrorResponse) : PresentationOutcome()
}
