package com.ewc.eudi_wallet_oidc_android.services.reissuance

import com.ewc.eudi_wallet_oidc_android.models.AuthorizationDetail
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.CredentialRequestEncryptionInfo
import com.ewc.eudi_wallet_oidc_android.models.ECKeyWithAlgEnc
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedCredentialResponse
import com.nimbusds.jose.jwk.ECKey
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
        interactiveAuthorizationEndpoint: String?,
        dpopKey: ECKey?,
        attachKeyAttestation: Boolean = false,
        keyAttestationJwt: String? = null,
        /** The client_id of the original grant, for the proof's `iss`. Null keeps `did`. */
        clientId: String? = null,
        /** The Authorization Server's `pre-authorized_grant_anonymous_access_supported`. */
        preAuthorizedGrantAnonymousAccessSupported: Boolean? = null
    ): WrappedCredentialResponse?

}