package com.ewc.eudi_wallet_oidc_android.services.issue

import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationMode
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationRequestInfo
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationRequestPolicy
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.CredentialSelection
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletAttestation
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.AuthorizationDetail
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.CredentialRequestEncryptionInfo
import com.ewc.eudi_wallet_oidc_android.models.ECKeyWithAlgEnc
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedCredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.WrappedCredentialResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedTokenResponse
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import org.json.JSONObject

interface IssueServiceInterface {


    /**
     * To process the credential offer request
     * @param data - will accept the full data which is scanned from the QR code or deep link
     *                  The data can contain credential offer or credential offer uri
     * @return Credential Offer
     */
    suspend fun resolveCredentialOffer(data: String?): WrappedCredentialOffer?

    /**
     * To process the authorisation request
     * The authorisation request is to grant access to the credential endpoint
     * @param did - DID created for the issuance
     * @param subJwk - for singing the requests
     * @param credentialOffer - To build the authorisation request
     * @param codeVerifier - to build the authorisation request
     * @param authorisationEndPoint - to build the authorisation request
     *
     * @return String - Uri with query parameter code with value short-lived authorisation code
     */
    suspend fun processAuthorisationRequest(
        did: String?,
        subJwk: JWK?,
        credentialOffer: CredentialOffer?,
        codeVerifier: String,
        authConfig: AuthorisationServerWellKnownConfiguration?,
        format: String? = "jwt_vc_json",
        docType: String? =null,
        issuerConfig: IssuerWellKnownConfiguration?,
        redirectUri: String? = null,
        isApiCallRequired: Boolean = false,
        walletUnitAttestationJWT: String? ,
        walletUnitProofOfPossession: String?,
    ): String?

    /**
     * The authorization request.
     *
     * Replaces [processAuthorisationRequest], whose `String?` meant six different things and left
     * the caller re-parsing query parameters off a URL to work out which. Switch on
     * [AuthorizationResponse.outcome].
     *
     * @param session the offer and the two metadata documents, from the offer and discovery steps
     * @param wallet the DID and key this authorization is bound to
     * @param attestation the wallet unit attestation and its proof of possession, when the issuer
     *   requires them; null sends no `OAuth-Client-Attestation` headers
     * @param codeVerifier PKCE (RFC 7636). Owned by the caller because the **token request needs the
     *   same value**; the SDK only derives the challenge from it.
     * @param selection overrides the format and doctype the session implies; both are derived when
     *   left null
     * @param redirectUri where the authorization server should send the user back to. Defaults to
     *   `openid://callback`. Whatever is used is returned as
     *   [AuthorizationRequestInfo.redirectUri] and **must be repeated verbatim in the token
     *   request** (RFC 6749 section 4.1.3)
     * @param mode [AuthorizationMode.Browser] for a scanned offer (RFC 8252), or
     *   [AuthorizationMode.InApp] for first-party non-interactive flows such as the
     *   wallet-provider attestation bootstrap
     */
    suspend fun requestAuthorization(
        session: IssuanceSession,
        wallet: WalletIdentity,
        attestation: WalletAttestation? = null,
        codeVerifier: String,
        selection: CredentialSelection = CredentialSelection(),
        redirectUri: String? = null,
        mode: AuthorizationMode = AuthorizationMode.Browser,
        policy: AuthorizationRequestPolicy = AuthorizationRequestPolicy.Default,
    ): AuthorizationResponse

    /**
     * To process the token,
     *
     * @param did
     * @param tokenEndPoint
     * @param code - If the credential offer is pre authorised, then use the pre authorised code from the credential offer
     *              else use the code from the previous function - processAuthorisationRequest
     * @param codeVerifier - use the same code verifier used for processAuthorisationRequest
     * @param isPreAuthorisedCodeFlow - boolean value to notify its a pre authorised request
     *                                  if pre-authorized_code is present
     * @param userPin - optional value, if the user_pin_required is true
     *              PIN will be provided by the user
     *
     * @return Token response
     */
    /**
     * Answers an authorization server that asked for an ID token rather than authorizing directly.
     *
     * Was public on the implementation but missing here, so a host could reach it only by parsing
     * the URL [processAuthorisationRequest] returned.
     */
    suspend fun processAuthorisationRequestUsingIdToken(
        did: String?,
        authorisationEndPoint: String?,
        location: String?,
        subJwk: JWK?
    ): String?

    suspend fun processTokenRequest(
        did: String?,
        tokenEndPoint: String?,
        code: String?,
        codeVerifier: String?,
        isPreAuthorisedCodeFlow: Boolean?,
        userPin: String?,
        version: Int?,
        walletUnitAttestationJWT: String? ,
        walletUnitProofOfPossession: String?,
        redirectUri: String? = null,
        dpopKey: ECKey?
    ): WrappedTokenResponse?

    /**
     * To process the credential, credentials can be issued in two ways,
     *     intime and deferred
     *
     *     If its intime, then we will receive the credential as the response
     *     If its deferred, then we will get he acceptance token and use this acceptance token to call deferred
     *
     * @param did
     * @param subJwk
     * @param nonce
     * @param credentialOffer
     * @param issuerConfig
     * @param accessToken
     * @param format
     *
     * @return credential response
     */
    suspend fun processCredentialRequest(
        did: String?,
        subJwk: JWK?,
        nonce: String?,
        credentialOffer: CredentialOffer?,
        issuerConfig: IssuerWellKnownConfiguration?,
        accessToken: String?,
        format: String
    ): WrappedCredentialResponse?

    suspend fun processCredentialRequest(
        did: String?,
        subJwk: JWK?,
        nonce: String?,
        credentialOffer: CredentialOffer?,
        issuerConfig: IssuerWellKnownConfiguration?,
        accessToken: TokenResponse?,
        authorizationDetail: AuthorizationDetail?,
        index: Int,
        ecKeyWithAlgEnc:ECKeyWithAlgEnc? =null,
        credentialRequestEncryptionInfo: CredentialRequestEncryptionInfo?,
        authConfig: AuthorisationServerWellKnownConfiguration?,
        dpopKey: ECKey?,
        attachKeyAttestation: Boolean = false,
        keyAttestationJwt: String? = null
    ): WrappedCredentialResponse?

    /**
     * For issuance of the deferred credential.
     * @param acceptanceToken - token which we got from credential request
     * @param deferredCredentialEndPoint - end point to call the deferred credential
     *
     * @return Credential response
     */
    suspend fun processDeferredCredentialRequest(
        acceptanceToken: String?,
        deferredCredentialEndPoint: String?,
        ecKeyWithAlgEnc: ECKeyWithAlgEnc? = null,
        credentialRequestEncryptionInfo: CredentialRequestEncryptionInfo?
    ): WrappedCredentialResponse?
    suspend fun processDeferredCredentialRequestV2(
        transactionId: String?,
        accessToken: String?,
        deferredCredentialEndPoint: String?,
        ecKeyWithAlgEnc: ECKeyWithAlgEnc? = null,
        credentialRequestEncryptionInfo: CredentialRequestEncryptionInfo?,
        dpopKey: ECKey? = null
    ): WrappedCredentialResponse?

    /**
     * Get format from IssuerWellKnownConfiguration
     *
     * @param issuerConfig
     * @param type
     */
    fun getFormatFromIssuerConfig(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?
    ): String?

    /**
     * Get types from credential offer
     *
     * @param credentialOffer
     * @return
     */
    fun getTypesFromCredentialOffer(
        credentialOffer: CredentialOffer?,
        index: Int? = 0
    ): ArrayList<String>

    /**
     * Get types from Issuer Config
     *
     * @param issuerConfig
     * @param type
     * @return
     */
    fun getTypesFromIssuerConfig(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?
    ): Any?
    fun getTypesFromIssuerConfig(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?,
        version:Int? = 2,
    ): Any?

    /**
     * Get types from Issuer Config
     *
     * @param issuerConfig
     * @param type
     * @return
     */
    fun getCryptoFromIssuerConfig(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?
    ): ArrayList<String>?

    fun isCredentialMetaDataAvailable(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?,
        version: Int? = 2
    ): Boolean
}