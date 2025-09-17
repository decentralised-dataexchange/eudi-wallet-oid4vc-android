package com.ewc.eudi_wallet_oidc_android.services.reissuance

import com.ewc.eudi_wallet_oidc_android.models.AuthorizationDetail
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.CredentialRequestEncryptionInfo
import com.ewc.eudi_wallet_oidc_android.models.ECKeyWithAlgEnc
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedCredentialResponse
import com.nimbusds.jose.jwk.JWK

interface ReIssuanceServiceInterface {
    suspend fun reIssueCredential(
        did: String?,
        subJwk: JWK?,
        nonce: String?,
        credentialOffer: CredentialOffer?,
        issuerConfig: IssuerWellKnownConfiguration?,
        accessToken: TokenResponse?,
        authorizationDetail: AuthorizationDetail?,
        index: Int,
        ecKeyWithAlgEnc:ECKeyWithAlgEnc?,
        credentialRequestEncryptionInfo: CredentialRequestEncryptionInfo?,
        interactiveAuthorizationEndpoint: String?
    ): WrappedCredentialResponse?

}