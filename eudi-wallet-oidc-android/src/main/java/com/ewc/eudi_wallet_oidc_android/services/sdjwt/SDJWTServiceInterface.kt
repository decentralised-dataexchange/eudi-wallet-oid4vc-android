package com.ewc.eudi_wallet_oidc_android.services.sdjwt

import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.github.decentraliseddataexchange.presentationexchangesdk.models.MatchedCredential
import com.nimbusds.jose.jwk.ECKey

interface SDJWTServiceInterface {

    fun calculateSHA256Hash(inputString: String?): String?

    fun createSDJWTR(
        credential: String?,
        presentationRequest: PresentationRequest,
        subJwk: ECKey
    ): String?

    fun processDisclosuresWithPresentationDefinition(
        credential: String?,
        presentationDefinition: PresentationDefinition
    ): String?

    fun updateIssuerJwtWithDisclosures(
        credential: String?
    ): String?
}