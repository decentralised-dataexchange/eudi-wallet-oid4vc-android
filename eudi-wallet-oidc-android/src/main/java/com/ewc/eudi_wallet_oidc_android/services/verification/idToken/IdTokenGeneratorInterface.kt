package com.ewc.eudi_wallet_oidc_android.services.verification.idToken

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.nimbusds.jose.jwk.JWK

interface IdTokenGeneratorInterface {
    fun generateIdToken(
        presentationRequest: PresentationRequest,
        did: String?,
        subJwk: JWK?
    ): String?
}