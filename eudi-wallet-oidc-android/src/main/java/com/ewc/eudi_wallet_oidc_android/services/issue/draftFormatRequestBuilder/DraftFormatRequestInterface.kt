package com.ewc.eudi_wallet_oidc_android.services.issue.draftFormatRequestBuilder

import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.CredentialRequest
import com.ewc.eudi_wallet_oidc_android.models.CredentialRequestEncryptionInfo
import com.ewc.eudi_wallet_oidc_android.models.ECKeyWithAlgEnc
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.WrappedCredentialResponse

interface DraftFormatRequestInterface{

    fun buildAuthorizationRequest(
        credentialOffer: CredentialOffer?,
        format: String?,
        doctype: String?
    ): String

    fun buildAuthorizationRequest(
        credentialOffer: CredentialOffer?,
        format: String?,
        doctype: String?,
        version: Int? = 2,
        issuerConfig: IssuerWellKnownConfiguration?
    ): String

    fun buildCredentialRequest(
        credentialOffer: CredentialOffer?,
        issuerConfig: IssuerWellKnownConfiguration?,
        format: String?,
        jwt: String,
        doctype: String?,
        index: Int
    ): CredentialRequest

    fun parseDraftCredentialOffer(credentialOfferJson: String?): CredentialOffer?

    fun getTxCodeParamKey(version: Int?): String?

    suspend fun processDeferredCredentialRequest(
        acceptanceToken: String?,
        deferredCredentialEndPoint: String?,
        ecKeyWithAlgEnc: ECKeyWithAlgEnc?,
        credentialRequestEncryptionInfo: CredentialRequestEncryptionInfo?
    ): WrappedCredentialResponse?

    fun getTypesFromIssuerConfig(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?
    ): Any?
}