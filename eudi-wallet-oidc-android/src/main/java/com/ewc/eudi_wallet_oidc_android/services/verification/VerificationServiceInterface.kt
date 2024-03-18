package com.ewc.eudi_wallet_oidc_android.services.verification

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.nimbusds.jose.jwk.ECKey

interface VerificationServiceInterface {

    /**
     * Authorisation requests can be presented to the wallet by verifying in two ways:
     * 1) by value
     * 2) by reference as defined in JWT-Secured Authorization Request (JAR) via use of request_uri.
     *      The custom URL scheme for authorisation requests is openid4vp://.
     *
     * @param data - will accept the full data which is scanned from the QR code or deep link
     *
     * @return PresentationRequest
     */
    suspend fun processAuthorisationRequest(data: String?): PresentationRequest?

    /**
     * Authorisation response is sent by constructing the vp_token and presentation_submission values.
     * @param did
     * @param subJwk
     * @param presentationRequest
     * @param credentialList - filtered credential list by presentationRequest
     *
     * @return String - url
     */
    suspend fun sendVPToken(
        did: String?,
        subJwk: ECKey?,
        presentationRequest: PresentationRequest,
        credentialList:List<String>
    ):String?
}