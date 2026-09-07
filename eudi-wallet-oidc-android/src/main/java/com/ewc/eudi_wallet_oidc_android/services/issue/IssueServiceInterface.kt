package com.ewc.eudi_wallet_oidc_android.services.issue

import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationMode
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationRequestInfo
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationRequestPolicy
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.CredentialSelection
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.CredentialEncryption
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.CredentialOutcome
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.CredentialRequestPolicy
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.CredentialSubject
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletAttestation
import com.ewc.eudi_wallet_oidc_android.services.issue.token.TokenGrant
import com.ewc.eudi_wallet_oidc_android.services.issue.token.TokenRequestPolicy
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
     * @param preAuthorizedGrantAnonymousAccessSupported - the Authorization Server's
     *              `pre-authorized_grant_anonymous_access_supported`. When true the pre-authorized
     *              request sends no `client_id`; absent or false, it sends the wallet's client identity.
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
        dpopKey: ECKey?,
        preAuthorizedGrantAnonymousAccessSupported: Boolean? = null
    ): WrappedTokenResponse?

    /**
     * The token request.
     *
     * Replaces [processTokenRequest], whose loose `code` / `codeVerifier` /
     * `isPreAuthorisedCodeFlow` / `userPin` parameters made illegal combinations expressible. The
     * grant is a sealed [TokenGrant], so section 6.1's "`tx_code` MUST only be used if the
     * grant_type is `urn:ietf:params:oauth:grant-type:pre-authorized_code`" cannot be broken.
     *
     * Whether a Transaction Code is *required* is read from the offer, not from whether one was
     * supplied: section 6.1 obliges the wallet to send it "if a `tx_code` object was present in the
     * Credential Offer (including if the object was empty)".
     *
     * @param grant [TokenGrant.PreAuthorized] or [TokenGrant.AuthorizationCode]; the offer decides
     *   which. The latter's `redirectUri` must be the value the authorization request sent --
     *   `AuthorizationResponse.request.redirectUri` (RFC 6749 section 4.1.3).
     * @param attestation carries the wallet unit attestation, its proof of possession **and the
     *   DPoP key**: ARF TS3 requires that key to be the one the attestation names in `cnf`, and
     *   keeping the three together is what makes that checkable rather than a mismatch a caller can
     *   make silently.
     * @param dpopNonce a nonce from an earlier `DPoP-Nonce` header, when one has been seen.
     */
    suspend fun requestToken(
        session: IssuanceSession,
        wallet: WalletIdentity,
        attestation: WalletAttestation? = null,
        grant: TokenGrant,
        dpopNonce: String? = null,
        policy: TokenRequestPolicy = TokenRequestPolicy.Default,
    ): WrappedTokenResponse

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

    @Deprecated(
        "Fourteen parameters, four of which pair up and two of which are dead. Use requestCredential, which takes a CredentialSubject and returns a CredentialOutcome.",
        ReplaceWith("requestCredential(session, wallet, token, subject)"),
    )
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
        keyAttestationJwt: String? = null,
        /** The client_id the token request used, for the proof's `iss`. Null keeps `did`. */
        clientId: String? = null
    ): WrappedCredentialResponse?

    /**
     * The credential request.
     *
     * Replaces the fourteen-parameter form above. What each change buys:
     *
     *  - `credentialOffer` + `issuerConfig` + `authConfig` become one [IssuanceSession] -- and
     *    `authConfig` was never read;
     *  - `did` + `subJwk` become one [WalletIdentity], as in the authorization and token steps;
     *  - `authorizationDetail` + `index` become one [CredentialSubject], which makes section 8.2's
     *    "`credential_identifier` ... MUST NOT be present with `credential_configuration_id`"
     *    unrepresentable rather than merely unwritten, and removes an unguarded `get(index)`;
     *  - `ecKeyWithAlgEnc` + `credentialRequestEncryptionInfo` become one [CredentialEncryption],
     *    since asking for an encrypted response over a plaintext request is not a thing to express;
     *  - `attachKeyAttestation` + `keyAttestationJwt` become one nullable attestation -- the boolean
     *    only chose between attaching one and logging that none arrived;
     *  - the DPoP key travels inside [WalletAttestation], where ARF TS3's `cnf` rule is checkable.
     *
     * @param nonce overrides the `c_nonce`. Left null the SDK obtains one: from the Nonce Endpoint
     *   when the issuer publishes one (section 7 -- it is unauthenticated), otherwise from the token
     *   response. Callers used to do this themselves, which is why one nonce was reused for every
     *   credential in a multi-credential offer.
     * @param dpopNonce carry `WrappedTokenResponse.dpopNonce` here; RFC 9449 section 8.2 makes
     *   using the most recent nonce a MUST.
     */
    suspend fun requestCredential(
        session: IssuanceSession,
        wallet: WalletIdentity,
        token: TokenResponse,
        subject: CredentialSubject,
        attestation: WalletAttestation? = null,
        keyAttestation: String? = null,
        encryption: CredentialEncryption? = null,
        nonce: String? = null,
        dpopNonce: String? = null,
        policy: CredentialRequestPolicy = CredentialRequestPolicy.Default,
    ): CredentialOutcome

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