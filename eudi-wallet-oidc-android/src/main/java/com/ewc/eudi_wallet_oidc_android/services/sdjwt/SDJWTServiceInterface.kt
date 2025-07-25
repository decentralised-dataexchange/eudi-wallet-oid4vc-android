package com.ewc.eudi_wallet_oidc_android.services.sdjwt

import com.ewc.eudi_wallet_oidc_android.models.CredentialList
import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.models.InputDescriptors
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.github.decentraliseddataexchange.presentationexchangesdk.models.MatchedCredential
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK

interface SDJWTServiceInterface {

    fun calculateSHA256Hash(inputString: String?): String?

    suspend  fun createSDJWTR(
        credential: String?,
        queryItem: Any,
        format: String,
        subJwk: JWK
    ): String?

    suspend  fun processDisclosuresWithPresentationDefinition(
        credential: String?,
        inputDescriptors: InputDescriptors,
        format:String
    ): String?
    suspend  fun processDisclosuresWithDCQL(
        credential: String?,
        credentialList: CredentialList?,
        format:String
    ): String?

    fun updateIssuerJwtWithDisclosures(
        credential: String?
    ): String?
}