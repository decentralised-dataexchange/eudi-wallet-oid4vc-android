package com.ewc.eudi_wallet_oidc_android.services.issue

import android.net.Uri
import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.AuthorizationDetail
import com.ewc.eudi_wallet_oidc_android.models.AuthorizationDetails
import com.ewc.eudi_wallet_oidc_android.models.ClientMetaDataas
import com.ewc.eudi_wallet_oidc_android.models.CredentialDefinition
import com.ewc.eudi_wallet_oidc_android.models.CredentialDetails
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.CredentialRequest
import com.ewc.eudi_wallet_oidc_android.models.CredentialResponse
import com.ewc.eudi_wallet_oidc_android.models.CredentialTypeDefinition
import com.ewc.eudi_wallet_oidc_android.models.Credentials
import com.ewc.eudi_wallet_oidc_android.models.ECKeyWithAlgEnc
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.Jwt
import com.ewc.eudi_wallet_oidc_android.models.ProofV3
import com.ewc.eudi_wallet_oidc_android.models.ProofsV3
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.models.VpFormatsSupported
import com.ewc.eudi_wallet_oidc_android.models.WrappedCredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.WrappedCredentialResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedTokenResponse
import com.ewc.eudi_wallet_oidc_android.models.v1.CredentialOfferEbsiV1
import com.ewc.eudi_wallet_oidc_android.models.v1.CredentialOfferEwcV1
import com.ewc.eudi_wallet_oidc_android.models.v2.CredentialOfferEwcV2
import com.ewc.eudi_wallet_oidc_android.models.v2.DeferredCredentialRequestV2
import com.ewc.eudi_wallet_oidc_android.services.UriValidationFailed
import com.ewc.eudi_wallet_oidc_android.services.UrlUtils
import com.ewc.eudi_wallet_oidc_android.services.codeVerifier.CodeVerifierService
import com.ewc.eudi_wallet_oidc_android.services.issue.credentialResponseEncryption.CredentialEncryptionBuilder
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.CredentialOfferPolicy
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationMode
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationRequestPolicy
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationRequestResolver
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationOutcome
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.CredentialSelection
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.details.AuthorizationDetailsBuilder
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.idtoken.IdTokenResponder
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletAttestation
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.CredentialOfferResolver
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.utils.ErrorHandler
import com.ewc.eudi_wallet_oidc_android.services.utils.ProofService
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse.JWEEncrypter
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonSyntaxException
import com.google.gson.reflect.TypeToken
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.ResponseBody
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.util.Base64
import retrofit2.Response
import java.util.Date
import java.util.UUID
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.KeyAttestationService
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletUnitAttestationHeaders
import com.ewc.eudi_wallet_oidc_android.models.CredentialRequestEncryptionInfo
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall
import com.ewc.eudi_wallet_oidc_android.services.utils.DPoPProofService
import java.io.IOException
import kotlin.collections.get

/**
 * @param offerPolicy what the SDK accepts when resolving a credential offer. Defaults to the
 *   permissive [CredentialOfferPolicy.Default]; pass [CredentialOfferPolicy.Strict] to require
 *   OpenID4VCI 1.0 exactly (https only, JSON enforced, no draft offers).
 */
class IssueService(
    private val offerPolicy: CredentialOfferPolicy = CredentialOfferPolicy.Default,
) : IssueServiceInterface {

    private val offerResolver = CredentialOfferResolver(policy = offerPolicy)


    /**
     * To process the credential offer request
     *
     * @param data - will accept the full data which is scanned from the QR
     *     code or deep link The data can contain credential offer or
     *     credential offer uri
     * @return Credential Offer, or a wrapper carrying an errorResponse describing why it could
     *     not be resolved. Never null.
     *
     * Resolution lives in [CredentialOfferResolver]: transfer mechanisms are pluggable
     * [com.ewc.eudi_wallet_oidc_android.services.issue.offer.source.CredentialOfferSource]s and
     * each supported spec revision has its own
     * [com.ewc.eudi_wallet_oidc_android.services.issue.offer.parser.CredentialOfferParser],
     * with OpenID4VCI 1.0 tried first.
     */
    override suspend fun resolveCredentialOffer(data: String?): WrappedCredentialOffer =
        offerResolver.resolve(data)

    /**
     * The authorization request.
     *
     * A delegation to `services/issue/authorization/`, where each way of putting the request to the
     * authorization server is an `AuthorizationRequestTransport` -- the IAR profile extension, PAR,
     * the in-app call, and the browser -- consulted in that order, and the parameters they all
     * share are assembled once.
     *
     * @return the same overloaded URL string this has always returned. Prefer
     *   [requestAuthorization], which names the outcome instead of leaving the caller to work it
     *   out from query parameters.
     */
    @Deprecated(
        "Returns a URL that means six different things. Use requestAuthorization, which returns AuthorizationResponse.",
        ReplaceWith("requestAuthorization(...)"),
    )
    override suspend fun processAuthorisationRequest(
        did: String?,
        subJwk: JWK?,
        credentialOffer: CredentialOffer?,
        codeVerifier: String,
        authConfig: AuthorisationServerWellKnownConfiguration?,
        format: String?,
        docType: String?,
        issuerConfig: IssuerWellKnownConfiguration?,
        redirectUri: String?,
        isApiCallRequired: Boolean,
        walletUnitAttestationJWT: String?,
        walletUnitProofOfPossession: String?,
    ): String? {
        val result = requestAuthorization(
            session = IssuanceSession(credentialOffer, issuerConfig, authConfig),
            wallet = WalletIdentity(did, subJwk),
            attestation = WalletAttestation(walletUnitAttestationJWT, walletUnitProofOfPossession),
            codeVerifier = codeVerifier,
            selection = CredentialSelection(format, docType),
            redirectUri = redirectUri,
            mode = if (isApiCallRequired) AuthorizationMode.InApp else AuthorizationMode.Browser,
        )

        // Flattened back onto the old contract, case for case. `location` is the redirect the
        // outcome was read from, which is exactly what this method used to return.
        return when (result.outcome) {
            AuthorizationOutcome.AUTHORIZATION_CODE -> result.location
            AuthorizationOutcome.OPEN_IN_BROWSER -> result.url
            AuthorizationOutcome.PRESENTATION_REQUIRED -> result.url
            AuthorizationOutcome.ID_TOKEN_REQUIRED -> result.url
            AuthorizationOutcome.FAILED -> result.location
        }
    }

    /**
     * The authorization request.
     *
     * Returns one [AuthorizationResponse]: the outcome, and what was sent to produce it. There is
     * deliberately no second "detailed" variant -- `request` is part of the contract, because the
     * caller needs `redirectUri` and `state` to finish the flow correctly.
     *
     * @param selection overrides what the session implies about the credential being requested;
     *   both fields are derived when left null.
     */
    override suspend fun requestAuthorization(
        session: IssuanceSession,
        wallet: WalletIdentity,
        attestation: WalletAttestation?,
        codeVerifier: String,
        selection: CredentialSelection,
        redirectUri: String?,
        mode: AuthorizationMode,
        policy: AuthorizationRequestPolicy,
    ): AuthorizationResponse {
        val types = getTypesFromCredentialOffer(session.credentialOffer)
        val format = selection.format
            ?: getFormatFromIssuerConfig(session.issuerConfig, types.lastOrNull())
        val resolved = selection.copy(format = format)

        val authorizationDetails = buildAuthorizationRequest(
            credentialOffer = session.credentialOffer,
            format = resolved.format,
            doctype = resolved.docType,
            issuerConfig = session.issuerConfig,
            version = session.offerVersion,
        )

        return AuthorizationRequestResolver(policy = policy).resolve(
            session = session,
            wallet = wallet,
            attestation = attestation,
            codeVerifier = codeVerifier,
            authorizationDetails = authorizationDetails,
            scopeTypes = types,
            selection = resolved,
            redirectUri = redirectUri,
            mode = mode,
        )
    }

    /**
     * Answers an authorization server that asked for an ID token rather than authorizing directly.
     *
     * A delegation to [IdTokenResponder]; the token itself is built exactly as before. Reached when
     * [requestAuthorization] answers with [AuthorizationOutcome.ID_TOKEN_REQUIRED], whose `url` is
     * the `location` to pass here.
     */
    override suspend fun processAuthorisationRequestUsingIdToken(
        did: String?,
        authorisationEndPoint: String?,
        location: String?,
        subJwk: JWK?
    ): String? = IdTokenResponder().respond(
        wallet = WalletIdentity(did, subJwk),
        authorisationEndPoint = authorisationEndPoint,
        location = location,
    )

    /**
     * The `authorization_details` parameter.
     *
     * A delegation to [AuthorizationDetailsBuilder]; the draft shapes live in its `legacy` package.
     */
    private fun buildAuthorizationRequest(
        credentialOffer: CredentialOffer?,
        format: String?,
        doctype: String?,
        version: Int? = 2,
        issuerConfig: IssuerWellKnownConfiguration?
    ): String = AuthorizationDetailsBuilder().build(
        session = IssuanceSession(credentialOffer, issuerConfig, null),
        format = format,
        docType = doctype,
        types = getTypesFromCredentialOffer(credentialOffer),
    )

    /**
     * To process the token,
     *
     * @param did
     * @param tokenEndPoint
     * @param code - If the credential offer is pre authorised, then use the
     *     pre authorised code from the credential offer else use the code from
     *     the previous function - processAuthorisationRequest
     * @param codeVerifier - use the same code verifier used for
     *     processAuthorisationRequest
     * @param isPreAuthorisedCodeFlow - boolean value to notify its a pre
     *     authorised request if pre-authorized_code is present
     * @param userPin - optional value, if the user_pin_required is true PIN
     *     will be provided by the user
     * @return Token response
     */
    override suspend fun processTokenRequest(
        did: String?,
        tokenEndPoint: String?,
        code: String?,
        codeVerifier: String?,
        isPreAuthorisedCodeFlow: Boolean?,
        userPin: String?,
        version: Int?,
        walletUnitAttestationJWT: String? ,
        walletUnitProofOfPossession: String?,
        redirectUri: String?,
        dpopKey: ECKey?
    ): WrappedTokenResponse? {
        val redirectURI = redirectUri ?: "openid://callback"
        val dpop = if (dpopKey != null && !tokenEndPoint.isNullOrEmpty()) {
            DPoPProofService().generateDPoP(
                httpMethod = "POST",
                targetUri = tokenEndPoint,
                dpopKey = dpopKey
            )
        } else null
        val headers = WalletUnitAttestationHeaders.build(
            walletUnitAttestationJWT,
            walletUnitProofOfPossession
        ).apply {
            if (!dpop.isNullOrEmpty()) {
                this["DPoP"] = dpop
            }
        }

        // --- invalid_client_attestation diagnostics (filter: adb logcat -s KaWatch) ---
        // The AS rejects the token request when the client attestation (WIA), its PoP, or
        // the DPoP binding is wrong. Log the decoded, non-secret fields so a rejection can
        // be traced to iss/aud/exp/nonce or a DPoP <-> WIA cnf key mismatch (the TS3 rule
        // that the DPoP key must equal the WIA cnf key).
        try {
            val dpopThumb = dpopKey?.computeThumbprint()?.toString()
            Log.d("KaWatch", "token request: endpoint=$tokenEndPoint clientId=$did grant=${if (isPreAuthorisedCodeFlow == true) "pre-authorized_code" else "authorization_code"} hasWIA=${walletUnitAttestationJWT != null} hasPoP=${walletUnitProofOfPossession != null} dpopKid=${dpopKey?.keyID} dpopThumb=$dpopThumb")
            val wia = decodeJwtPayloadForLog(walletUnitAttestationJWT)
            val wiaCnf = wia?.optJSONObject("cnf")?.optJSONObject("jwk")
            Log.d("KaWatch", "token request WIA: iss=${wia?.opt("iss")} sub=${wia?.opt("sub")} aud=${wia?.opt("aud")} iat=${wia?.opt("iat")} exp=${wia?.opt("exp")} cnf.jwk=$wiaCnf")
            val pop = decodeJwtPayloadForLog(walletUnitProofOfPossession)
            Log.d("KaWatch", "token request WIA-PoP: iss=${pop?.opt("iss")} aud=${pop?.opt("aud")} iat=${pop?.opt("iat")} exp=${pop?.opt("exp")} jti=${pop?.opt("jti")} nonce=${pop?.opt("nonce")}")
            val wiaCnfThumb = wiaCnf?.let { runCatching { ECKey.parse(it.toString()).computeThumbprint().toString() }.getOrNull() }
            Log.d("KaWatch", "token request key-binding: dpopThumb=$dpopThumb wiaCnfThumb=$wiaCnfThumb match=${dpopThumb != null && dpopThumb == wiaCnfThumb}")
        } catch (e: Exception) {
            Log.e("KaWatch", "token request: attestation diagnostics failed: ${e.message}")
        }

        val result = SafeApiCall.safeApiCallResponse {
            ApiManager.api.getService()?.getAccessTokenFromCode(
                tokenEndPoint ?: "",
                if (isPreAuthorisedCodeFlow == true) {
                    // Map for pre-authorized code flow
                    mutableMapOf(
                        "grant_type" to "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                        "pre-authorized_code" to (code ?: "")
                    ).apply {
                        if (userPin != null) {
                            if (version == 1) {
                                this["user_pin"] = userPin ?: ""
                            } else {
                                this["tx_code"] = userPin ?: ""
                            }
                        }
                    }
                } else {
                    // Map for authorization code flow
                    mutableMapOf(
                        "grant_type" to "authorization_code",
                        "code" to (code ?: ""),
                        "client_id" to (did ?: ""),
                        "code_verifier" to (codeVerifier ?: ""),
                        "redirect_uri" to (redirectURI)
                    )
                },
                headers
            )
        }

        return result.fold(
            onSuccess = { response ->
                when {
                    response.isSuccessful -> {
                        val lpid = response.headers()["legal-pid-attestation"]
                        val lpidPoP = response.headers()["legal-pid-attestation-pop"]
                        WrappedTokenResponse(
                            tokenResponse = response.body(),
                            legalPidAttestation = lpid,
                            legalPidAttestationPoP = lpidPoP,
                            dpop = dpop
                        )
                    }

                    (response.code() >= 400) -> {
                        try {
                            val errorBodyString = response.errorBody()?.string()
                            Log.e("KaWatch", "token endpoint ${response.code()} endpoint=$tokenEndPoint error=$errorBodyString")
                            WrappedTokenResponse(
                                errorResponse = ErrorHandler.processError(errorBodyString)
                            )
                        } catch (e: Exception) {
                            null
                        }
                    }

                    else -> null
                }
            },
            onFailure = { error ->
                Log.e("KaWatch", "token request FAILED endpoint=$tokenEndPoint error=${error.message}")
                println("Error while processing token request: ${error.message}")
                WrappedTokenResponse(
                    errorResponse = ErrorHandler.processError(error.message)
                )
            }
        )
    }

    /**
     * Decodes a JWT / SD-JWT payload to JSON for diagnostic logging only (no signature
     * check). Tolerates the SD-JWT trailing '~' and base64url without padding.
     */
    private fun decodeJwtPayloadForLog(jwt: String?): JSONObject? {
        if (jwt.isNullOrBlank()) return null
        return try {
            val parts = jwt.substringBefore("~").split(".")
            if (parts.size < 2) return null
            JSONObject(String(Base64.getUrlDecoder().decode(parts[1])))
        } catch (e: Exception) {
            Log.e("KaWatch", "decodeJwtPayloadForLog failed: ${e.message}")
            null
        }
    }


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
    override suspend fun processCredentialRequest(
        did: String?,
        subJwk: JWK?,
        nonce: String?,
        credentialOffer: CredentialOffer?,
        issuerConfig: IssuerWellKnownConfiguration?,
        accessToken: String?,
        format: String
    ): WrappedCredentialResponse? {
        val credentialsSupported = issuerConfig?.credentialsSupported
        val credentials = credentialOffer?.credentials
        val doctype: String? = if (format == "mso_mdoc") {
            when (credentialsSupported) {
                is Map<*, *> -> {
                    @Suppress("UNCHECKED_CAST")
                    val map = credentialsSupported as? Map<String, Any>
                    getDocType(map, credentials)
                }
                is List<*> -> {
                    @Suppress("UNCHECKED_CAST")
                    val list = credentialsSupported as? List<Map<String, Any>>
                    getDocType(list, credentials)
                }
                else -> null
            }
        } else {
            null
        }

        val jwt = ProofService().createProof(did, subJwk, nonce, issuerConfig,credentialOffer)
        if (jwt == null) {
            Log.e("IssueService", "Failed to create proof for credential request")
            return null
        }

        // Construct credential request
        val body = buildCredentialRequest(
            credentialOffer = credentialOffer,
            issuerConfig = issuerConfig,
            format = format,
            jwt = jwt,
            doctype = doctype,
            index = 0
        )

        // Use SafeApiCall for cleaner, safer call
        val result = SafeApiCall.safeApiCallResponse {
            ApiManager.api.getService()?.getCredential(
                issuerConfig?.credentialEndpoint ?: "",
                "application/json",
                "Bearer $accessToken",
                null,
                body
            )
        }

        return result.fold(
            onSuccess = { response ->
                when {
                    (response.code() >= 400) -> {
                        try {
                            WrappedCredentialResponse(
                                errorResponse = ErrorHandler.processError(response.errorBody()?.string())
                            )
                        } catch (e: Exception) {
                            null
                        }
                    }

                    response.isSuccessful -> {
                        val raw = response.body()?.string()
                        val parsed = Gson().fromJson(raw, CredentialResponse::class.java)
                        WrappedCredentialResponse(credentialResponse = parsed)
                    }

                    else -> null
                }
            },
            onFailure = { error ->
                println("Error while processing credential request: ${error.message}")
                WrappedCredentialResponse(
                    errorResponse = ErrorHandler.processError(error.message)
                )
            }
        )
    }

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
    override suspend fun processCredentialRequest(
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
        authConfig: AuthorisationServerWellKnownConfiguration?,
        dpopKey: ECKey?,
        attachKeyAttestation: Boolean,
        keyAttestationJwt: String?
    ): WrappedCredentialResponse? {
        val TAG = "processCredentialRequestKeyAttestation"

        val dpopHeaderValue =
            if (!issuerConfig?.credentialEndpoint.isNullOrEmpty()
                && dpopKey != null
                && accessToken?.accessToken != null
            ) {
                val athValue = DPoPProofService().computeAccessTokenHash(accessToken.accessToken)

                val claims = mapOf(
                    "ath" to athValue,
                )

                DPoPProofService().generateDPoP(
                    httpMethod = "POST",
                    targetUri = issuerConfig.credentialEndpoint ?: "",
                    dpopKey = dpopKey,
                    claims = claims
                )
            } else null

        val authHeaderValue = if (dpopHeaderValue != null) {
            "DPoP ${accessToken?.accessToken}"
        } else {
            "Bearer ${accessToken?.accessToken}"
        }

        val credentialEncryptionBuilder = CredentialEncryptionBuilder()
        // ARF TS3 v1.5: the wallet-provider-issued KA travels in the proof's
        // key_attestation header, bound to the same c_nonce as the proof.
        val keyAttestation = KeyAttestationService.forProof(
            keyAttestationJwt, attachKeyAttestation
        )
        Log.d("BankIdWatch", "credential request: attachKA=$attachKeyAttestation preMintedHardwareKA=${keyAttestationJwt != null} kaAttached=${keyAttestation != null} cNonce=$nonce auth=${if (dpopHeaderValue != null) "DPoP" else "Bearer"} endpoint=${issuerConfig?.credentialEndpoint}")
        Log.d("KaWatch", "credential request: attachKA=$attachKeyAttestation preMintedKA=${keyAttestationJwt != null} kaOnProof=${keyAttestation != null} cNonce=$nonce auth=${if (dpopHeaderValue != null) "DPoP" else "Bearer"} endpoint=${issuerConfig?.credentialEndpoint}")
        val jwt = ProofService().createProof(did, subJwk, nonce , issuerConfig,credentialOffer,index, keyAttestation)
        if (jwt == null) {
            Log.e("IssueService", "Failed to create proof for credential request")
            return null
        }

        val request: CredentialRequest = if (authorizationDetail != null && authorizationDetail.type == "openid_credential" && !authorizationDetail.credentialIdentifiers.isNullOrEmpty()) {
            Log.d(TAG,"entered first condition")
            CredentialRequest(
                credentialIdentifier = authorizationDetail.credentialIdentifiers.firstOrNull(),
                proof = ProofV3(jwt =  jwt, proofType = "jwt"),
            )
        }  else if (authorizationDetail !=null && authorizationDetail.type == "openid_credential" && issuerConfig?.nonceEndpoint!=null && !authorizationDetail.credentialConfigurationId.isNullOrBlank()) {
            Log.d(TAG,"entered second condition")
            CredentialRequest(
                credentialConfigurationId = authorizationDetail.credentialConfigurationId,
                proof = ProofV3(jwt =  jwt, proofType = "jwt"),
            )
        } else if (issuerConfig?.nonceEndpoint!=null && accessToken?.authorizationDetails.isNullOrEmpty()){
            // OpenID4VCI 1.0 (issuer publishes a nonce endpoint): the request
            // carries credential_configuration_id, never format+vct. The old
            // extra gate on cNonce==null dropped issuers that return a c_nonce
            // in the token response AS WELL (BankID), and they rejected the
            // legacy format+vct body with "Invalid request format".
            Log.d(TAG,"entered third condition")
            CredentialRequest(
                credentialConfigurationId = credentialOffer?.credentials?.get(index)?.types?.firstOrNull(),
                proof = ProofV3(jwt = jwt,proofType = "jwt"),
            )
        } else {
            Log.d(TAG,"entered else condition")
            val doctype = fetchDoctype(index,credentialOffer,issuerConfig)
            var types: ArrayList<String> = ArrayList()
            var format: String? = null
            try {
                types = credentialOffer?.credentials?.get(index)?.types
                    ?: credentialOffer?.credentials?.get(index)?.doctype?.let { arrayListOf(it) }
                            ?: ArrayList()
                format = IssueService().getFormatFromIssuerConfig(
                    issuerConfig,
                    types.lastOrNull() ?: ""
                )
            } catch (e: Exception) {
            }
            buildCredentialRequest(
                credentialOffer = credentialOffer,
                issuerConfig = issuerConfig,
                format = format,
                doctype = doctype,
                jwt = jwt, index = index
            )
        }
        if ((issuerConfig?.credentialsSupported is Map<*, *>) &&
            ((issuerConfig.credentialsSupported as Map<*, *>).values.firstOrNull() is Map<*, *>) &&
            ((issuerConfig.credentialsSupported as Map<*, *>).values.firstOrNull() as Map<*, *>).containsKey("credential_metadata")
        ) {
            request.proofs = ProofsV3(jwt = arrayListOf(jwt))
            request.proof = null
        }

        request.credentialResponseEncryption = credentialEncryptionBuilder.build(ecKeyWithAlgEnc)

        Gson().toJson(request).chunked(3000).forEachIndexed { i, chunk ->
            Log.d("BankIdWatch", "credential request body[$i]=$chunk")
        }

        // Safely perform network call using SafeApiCall
        val result = SafeApiCall.safeApiCallResponse {
            if (credentialRequestEncryptionInfo?.encryptionRequired == true) {
                if (credentialRequestEncryptionInfo.jwk != null) {
                    val type = object : TypeToken<Map<String, Any?>>() {}.type
                    val payload: Map<String, Any?> = Gson().fromJson(Gson().toJson(request), type)

                    val encryptedJwe = JWEEncrypter().encrypt(
                        payload = payload,
                        jwk = credentialRequestEncryptionInfo.jwk
                    )
                    val requestBody = encryptedJwe.toRequestBody("application/jwt".toMediaType())

                    ApiManager.api.getService()?.getCredentialEncrypted(
                        issuerConfig?.credentialEndpoint ?: "",
                        "application/jwt",
                        authHeaderValue,
                        dpopHeaderValue,
                        requestBody
                    )
                } else null
            } else {
                ApiManager.api.getService()?.getCredential(
                    issuerConfig?.credentialEndpoint ?: "",
                    "application/json",
                    authHeaderValue,
                    dpopHeaderValue,
                    request
                )
            }
        }

        return result.fold(
            onSuccess = { response ->
                when {
                    (response.code() >= 400) -> {
                        try {
                            val errorBody = response.errorBody()?.string()
                            Log.e("KaWatch", "credential endpoint ${response.code()}: $errorBody")
                            WrappedCredentialResponse(
                                errorResponse = ErrorHandler.processError(errorBody)
                            )
                        } catch (e: Exception) {
                            null
                        }
                    }

                    response.isSuccessful -> {
                        Log.d("KaWatch", "credential endpoint ${response.code()}: success")
                        parseCredentialResponse(response, ecKeyWithAlgEnc, credentialEncryptionBuilder)
                    }

                    else -> null
                }
            },
            onFailure = { error ->
                println("Error while processing credential request: ${error.message}")
                WrappedCredentialResponse(
                    errorResponse = ErrorHandler.processError(error.message)
                )
            }
        )
    }

     fun parseCredentialResponse(
        response: Response<ResponseBody>,
        ecKeyWithAlgEnc: ECKeyWithAlgEnc?,
        credentialEncryptionBuilder: CredentialEncryptionBuilder
    ): WrappedCredentialResponse? {
        val raw = response.body()?.string()
        val contentType = response.headers()["Content-Type"] ?: ""
        return if (contentType.contains("application/jwt", ignoreCase = true)) {

            if (ecKeyWithAlgEnc != null) {
                val privateKey = ecKeyWithAlgEnc.ecKey
                // Try decrypting the JWE
                val decryptedJson: String? = try {
                    credentialEncryptionBuilder.decryptJWE(raw ?: "", privateKey)
                } catch (ex: Exception) {
                    Log.e("CredentialRequest", "Decryption failed: ${ex.message}")
                    null
                }
                if (!decryptedJson.isNullOrEmpty()) {
                    try {
                        val parsedDecrypted = Gson().fromJson(
                            decryptedJson,
                            CredentialResponse::class.java
                        )
                        WrappedCredentialResponse(credentialResponse = parsedDecrypted)
                    } catch (ex: JsonSyntaxException) {
                        WrappedCredentialResponse(
                            errorResponse = ErrorHandler.processError(
                                ex.message ?: "Decrypted payload is not valid JSON"
                            )
                        )
                    }
                } else {
                    WrappedCredentialResponse(
                        errorResponse = ErrorHandler.processError(
                            "JWE Decryption failed or empty response"
                        )
                    )
                }
            } else {
                WrappedCredentialResponse(
                    errorResponse = ErrorHandler.processError(
                        "ecKey is null, cannot decrypt JWE"
                    )
                )
            }

        } else {
            try {
                val parsed = Gson().fromJson(raw, CredentialResponse::class.java)
                WrappedCredentialResponse(credentialResponse = parsed)
            } catch (ex: JsonSyntaxException) {
                WrappedCredentialResponse(
                    errorResponse = ErrorHandler.processError("Invalid JSON in response: ${ex.message}")
                )
            }
        }
    }

     fun fetchDoctype(
        index: Int,
        credentialOffer: CredentialOffer?,
        issuerConfig: IssuerWellKnownConfiguration?
    ): String? {
        return try {
            val credentials = credentialOffer?.credentials
            val types = credentials?.get(index)?.types
                ?: credentials?.get(index)?.doctype?.let { arrayListOf(it) }
                ?: arrayListOf()

            val format = IssueService().getFormatFromIssuerConfig(
                issuerConfig,
                types.lastOrNull().orEmpty()
            )

            val credentialsSupported = issuerConfig?.credentialsSupported

            if (format == "mso_mdoc") {
                when (credentialsSupported) {
                    is Map<*, *> -> {
                        @Suppress("UNCHECKED_CAST")
                        getDocType(credentialsSupported as? Map<String, Any>, credentials)
                    }
                    is List<*> -> {
                        @Suppress("UNCHECKED_CAST")
                        getDocType(credentialsSupported as? List<Map<String, Any>>, credentials)
                    }
                    else -> null
                }
            } else {
                null
            }
        } catch (e: Exception) {
            Log.e("doctypefetch", "Error: ${e.message}", e)
            null
        }
    }


    fun getDocType(
        credentialsSupported: Any?,
        credentials: ArrayList<Credentials>?
    ): String? {
        if (credentialsSupported == null || credentials.isNullOrEmpty()) {
            return null
        }

        if ((credentialsSupported is Map<*, *> && credentialsSupported.isEmpty()) ||
            (credentialsSupported is List<*> && credentialsSupported.isEmpty())) {
            return null
        }

        val credentialType = extractCredentialType(credentials)

        val matchingCredentialMap: Map<String, Any>? =
            credentialType?.let { getMatchingCredentialMap(credentialsSupported, it) }

        val matchingCredential = matchingCredentialMap?.let { convertToCredentialDetails(it) }
        return matchingCredential?.doctype
    }
    private fun extractCredentialType(credentials: ArrayList<Credentials>): String? {
        return credentials
            .asReversed()
            .firstOrNull { it?.types?.isNotEmpty() == true || it?.doctype != null }
            ?.let {
                (it.types?.lastOrNull { t -> t != null } as? String) ?: it.doctype
            } ?: null
    }
    private fun getMatchingCredentialMap(credentialsSupported: Any, credentialType: String): Map<String, Any>? {
        return when (credentialsSupported) {
            is Map<*, *> -> credentialsSupported[credentialType] as? Map<String, Any>
            is List<*> -> {
                try {
                    val matchedList = (credentialsSupported as? List<Map<String, Any>>)?.filter { item ->
                        val types = item["types"] as? List<*>
                        val lastType = types?.lastOrNull() as? String

                        if (lastType == credentialType) {
                            true
                        } else {
                            val docType = item["doctype"] as? String
                            docType != null && docType == credentialType
                        }
                    }
                    matchedList?.getOrNull(0)
                }catch (e:Exception){
                    null
                }
            }
            else -> null
        }
    }
    private fun convertToCredentialDetails(map: Map<String, Any>): CredentialDetails? {
        return try {
            val gson = GsonBuilder()
                .setLenient()
                .serializeNulls()
                .create()

            val jsonString = gson.toJson(map)
            gson.fromJson(jsonString, CredentialDetails::class.java)
        } catch (e: Exception) {
            println("Error converting map to CredentialDetails: ${e.message}")
            null
        }
    }

     fun buildCredentialRequest(
        credentialOffer: CredentialOffer?,
        issuerConfig: IssuerWellKnownConfiguration?,
        format: String?,
        jwt: String,
        doctype: String?,
        index: Int
    ): CredentialRequest {

        val gson = Gson()
        var credentialDefinitionNeeded = false
        try {
            if (issuerConfig?.credentialsSupported is Map<*, *>)
                credentialDefinitionNeeded = true

        } catch (e: Exception) {
            credentialDefinitionNeeded = true
        }
        if (format == "mso_mdoc") {
            return CredentialRequest(
                format = format,
                doctype = doctype,
                proof = ProofV3(
                    proofType = "jwt",
                    jwt = jwt
                )
            )
        } else {
            if (credentialDefinitionNeeded) {
                var types: ArrayList<String>? = getTypesFromCredentialOffer(credentialOffer)
                when (val data = getTypesFromIssuerConfig(
                    issuerConfig,
                    type = if (types?.isNotEmpty() == true) types.last() else "",
                    version = credentialOffer?.version,
                )) {
                    is ArrayList<*> -> {
                        return CredentialRequest(
                            credentialDefinition = CredentialDefinition(type = data as ArrayList<String>),
                            format = format,
                            proof = ProofV3(
                                proofType = "jwt",
                                jwt = jwt
                            )
                        )
                    }

                    is String -> {
                        return CredentialRequest(
                            vct = data as String,
                            format = format,
                            proof = ProofV3(
                                proofType = "jwt",
                                jwt = jwt
                            )
                        )
                    }
                }

                return CredentialRequest(
                    credentialDefinition = CredentialDefinition(type = types),
                    format = format,
                    proof = ProofV3(
                        proofType = "jwt",
                        jwt = jwt
                    )
                )
            } else {
                return CredentialRequest(
                    types = getTypesFromCredentialOffer(credentialOffer),
                    format = format,
                    proof = ProofV3(
                        proofType = "jwt",
                        jwt = jwt
                    )
                )
            }
        }


    }


    /**
     * For issuance of the deferred credential.
     *
     * @param acceptanceToken - token which we got from credential request
     * @param deferredCredentialEndPoint - end point to call the deferred
     *     credential
     * @return Credential response
     */
    override suspend fun processDeferredCredentialRequest(
        acceptanceToken: String?,
        deferredCredentialEndPoint: String?,
        ecKeyWithAlgEnc: ECKeyWithAlgEnc?,
        credentialRequestEncryptionInfo: CredentialRequestEncryptionInfo?
    ): WrappedCredentialResponse? {
        val credentialEncryptionBuilder = CredentialEncryptionBuilder()
        return try {
            val result = SafeApiCall.safeApiCallResponse {
                ApiManager.api.getService()?.getDifferedCredential(
                    deferredCredentialEndPoint ?: "",
                    "Bearer $acceptanceToken",
                    CredentialRequest() // empty object
                )
            }

            result.fold(
                onSuccess = { response ->
                    parseCredentialResponse(response, ecKeyWithAlgEnc, credentialEncryptionBuilder)
                },
                onFailure = { error ->
                    println("Error while fetching deferred credential: ${error.message}")
                    null
                }
            )
        } catch (e: IOException) {
            println("IOException while fetching deferred credential: ${e.message}")
            null
        } catch (e: Exception) {
            println("Unexpected error while fetching deferred credential: ${e.message}")
            null
        }
    }

    override suspend fun processDeferredCredentialRequestV2(
        transactionId: String?,
        accessToken: String?,
        deferredCredentialEndPoint: String?,
        ecKeyWithAlgEnc: ECKeyWithAlgEnc?,
        credentialRequestEncryptionInfo: CredentialRequestEncryptionInfo?,
        dpopKey: ECKey?
    ): WrappedCredentialResponse? {
        val credentialEncryptionBuilder = CredentialEncryptionBuilder()
        // A DPoP-bound access token must stay DPoP-bound on the deferred
        // endpoint too: same key as the token request, fresh jti, ath.
        val dpopHeaderValue =
            if (dpopKey != null && !deferredCredentialEndPoint.isNullOrEmpty() && accessToken != null) {
                DPoPProofService().generateDPoP(
                    httpMethod = "POST",
                    targetUri = deferredCredentialEndPoint,
                    dpopKey = dpopKey,
                    claims = mapOf(
                        "ath" to DPoPProofService().computeAccessTokenHash(accessToken)
                    )
                )
            } else null
        val authHeaderValue = if (dpopHeaderValue != null) {
            "DPoP $accessToken"
        } else {
            "Bearer $accessToken"
        }
        return try {
            val result = SafeApiCall.safeApiCallResponse {
                if (credentialRequestEncryptionInfo?.encryptionRequired == true) {
                    val request = DeferredCredentialRequestV2(transactionId)
                    if (credentialRequestEncryptionInfo.jwk != null) {
                        val type = object : TypeToken<Map<String, Any?>>() {}.type
                        val payload: Map<String, Any?> = Gson().fromJson(Gson().toJson(request), type)

                        val encryptedJwe = JWEEncrypter().encrypt(
                            payload = payload,
                            jwk = credentialRequestEncryptionInfo.jwk
                        )
                        val requestBody = encryptedJwe
                            .toRequestBody("application/jwt".toMediaType())

                        ApiManager.api.getService()?.getDifferedCredentialV2Encrypted(
                            deferredCredentialEndPoint ?: "",
                            "application/jwt",
                            authHeaderValue,
                            requestBody,
                            dpop = dpopHeaderValue
                        )
                    } else {
                        null
                    }
                } else {
                    ApiManager.api.getService()?.getDifferedCredentialV2(
                        deferredCredentialEndPoint ?: "",
                        authHeaderValue,
                        DeferredCredentialRequestV2(transactionId),
                        dpop = dpopHeaderValue
                    )
                }
            }

            result.fold(
                onSuccess = { response ->
                    parseCredentialResponse(response, ecKeyWithAlgEnc, credentialEncryptionBuilder)
                },
                onFailure = { error ->
                    println("Error while fetching deferred credential V2: ${error.message}")
                    null
                }
            )
        } catch (e: IOException) {
            println("IOException while fetching deferred credential V2: ${e.message}")
            null
        } catch (e: Exception) {
            println("Unexpected error while fetching deferred credential V2: ${e.message}")
            null
        }
    }

    /**
     * Get format from IssuerWellKnownConfiguration
     *
     * @param issuerConfig
     * @param type
     */
    override fun getFormatFromIssuerConfig(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?
    ): String? {
        var format: String = "jwt_vc"
        val credentialOfferJsonString = Gson().toJson(issuerConfig)

        val jsonObject = JSONObject(credentialOfferJsonString)

        val credentialsSupported: Any = jsonObject.opt("credentials_supported") ?: return null

        when (credentialsSupported) {
            is JSONObject -> {
                try {
                    val credentialSupported = credentialsSupported.getJSONObject(type ?: "")
                    format = credentialSupported.getString("format")
                } catch (e: Exception) {
                }
            }
            is JSONArray -> {
                try {
                    for (i in 0 until credentialsSupported.length()) {
                        val item = credentialsSupported.optJSONObject(i) ?: continue

                        // First check "types" array
                        val typesArray = item.optJSONArray("types")
                        if (typesArray != null) {
                            if ((0 until typesArray.length()).any { typesArray.optString(it) == type }) {
                                format = item.optString("format", format)
                                break
                            }
                        } else {
                            // Fallback: check "doctype" string
                            val docType = item.optString("doctype", "")
                            if (docType.isNotEmpty() && docType == type) {
                                format = item.optString("format", format)
                                break
                            }
                        }
                    }
                } catch (e: Exception) {
                    // ignore or log
                }
            }

            else -> {
                // Neither JSONObject nor JSONArray
                println("Child is neither JSONObject nor JSONArray")
            }
        }

        return format
    }

    /**
     * Get types from IssuerWellKnownConfiguration
     *
     * @param issuerConfig
     * @param type
     */
    override fun getTypesFromIssuerConfig(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?
    ): Any? {
        var types: ArrayList<String> = ArrayList()
        // Check if issuerConfig is null
        if (issuerConfig == null) {
            return null
        }
        try {
            val credentialOfferJsonString = Gson().toJson(issuerConfig)
            // Check if credentialOfferJsonString is null or empty
            if (credentialOfferJsonString.isNullOrEmpty()) {
                return null
            }
            val jsonObject = JSONObject(credentialOfferJsonString)

            val credentialsSupported: Any = jsonObject.opt("credentials_supported") ?: return null
            when (credentialsSupported) {
                is JSONObject -> {
                    try {
                        val credentialSupported = credentialsSupported.getJSONObject(type ?: "")
                        val format =
                            if (credentialSupported.has("format")) credentialSupported.getString("format") else ""

                        if (format == "vc+sd-jwt" || format == "dc+sd-jwt") {
                            return credentialSupported.getJSONObject("credential_definition")
                                .getString("vct")
                        } else {
                            val typeFromCredentialIssuer: JSONArray =
                                credentialSupported.getJSONObject("credential_definition")
                                    .getJSONArray("type")
                            for (i in 0 until typeFromCredentialIssuer.length()) {
                                // Get each JSONObject from the JSONArray
                                val type: String = typeFromCredentialIssuer.getString(i)
                                types.add(type)
                            }
                            return types
                        }
                    } catch (e: Exception) {
                    }
                }

                is JSONArray -> {
                    try {
                        for (i in 0 until credentialsSupported.length()) {
                            val jsonObject: JSONObject = credentialsSupported.getJSONObject(i)

                            // Get the "types" JSONArray
                            val typesArray = jsonObject.getJSONArray("types")

                            // Check if the string is present in the "types" array
                            for (j in 0 until typesArray.length()) {
                                if (typesArray.getString(j) == type) {
                                    val format =
                                        if (jsonObject.has("format")) jsonObject.getString("format") else ""

                                    if (format == "vc+sd-jwt" || format == "dc+sd-jwt") {
                                        return jsonObject.getJSONObject("credential_definition")
                                            .getString("vct")
                                    } else {
                                        val typeFromCredentialIssuer: JSONArray =
                                            jsonObject.getJSONObject("credential_definition")
                                                .getJSONArray("type")
                                        for (i in 0 until typeFromCredentialIssuer.length()) {
                                            // Get each JSONObject from the JSONArray
                                            val type: String = typeFromCredentialIssuer.getString(i)
                                            types.add(type)
                                        }
                                        return types
                                    }
                                    break
                                }
                            }
                        }
                    } catch (e: Exception) {
                    }
                }

                else -> {
                    // Neither JSONObject nor JSONArray
                    println("Child is neither JSONObject nor JSONArray")
                }
            }
        } catch (e: JSONException) {
            Log.e("getTypesFromIssuerConfig", "Error parsing JSON", e)
        }

        return types
    }

    override fun getTypesFromIssuerConfig(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?,
        version: Int?
    ): Any? {
        var types: ArrayList<String> = ArrayList()
        // Check if issuerConfig is null
        if (issuerConfig == null) {
            return null
        }
        when (version) {
            1 -> {
                return getTypesFromIssuerConfig(issuerConfig, type)
            }

            else -> {


                try {
                    val credentialOfferJsonString = Gson().toJson(issuerConfig)
                    // Check if credentialOfferJsonString is null or empty
                    if (credentialOfferJsonString.isNullOrEmpty()) {
                        return null
                    }
                    val jsonObject = JSONObject(credentialOfferJsonString)

                    val credentialsSupported: Any =
                        jsonObject.opt("credentials_supported") ?: return null
                    when (credentialsSupported) {
                        is JSONObject -> {
                            try {
                                val credentialSupported =
                                    credentialsSupported.getJSONObject(type ?: "")
                                val format =
                                    if (credentialSupported.has("format")) credentialSupported.getString(
                                        "format"
                                    ) else ""

                                if (format == "vc+sd-jwt" || format == "dc+sd-jwt") {
                                    return credentialSupported.getString("vct")
                                } else {
                                    val typeFromCredentialIssuer: JSONArray =
                                        credentialSupported.getJSONObject("credential_definition")
                                            .getJSONArray("type")
                                    for (i in 0 until typeFromCredentialIssuer.length()) {
                                        // Get each JSONObject from the JSONArray
                                        val type: String = typeFromCredentialIssuer.getString(i)
                                        types.add(type)
                                    }
                                    return types
                                }
                            } catch (e: Exception) {
                            }
                        }
                    }
                } catch (e: Exception) {

                }


            }
        }

        return types
    }

    /**
     * Get types from credential offer
     *
     * @param credentialOffer
     * @return
     */
    override fun getTypesFromCredentialOffer(
        credentialOffer: CredentialOffer?,
        index: Int?
    ): ArrayList<String> {
        var types: ArrayList<String> = ArrayList()
        val credentialOfferJsonString = Gson().toJson(credentialOffer)
        try {
            try {
                val credentialOffer =
                    Gson().fromJson(credentialOfferJsonString, CredentialOffer::class.java)
                if( credentialOffer.credentials?.get(index?:0)?.format == "mso_mdoc")
                {
                    credentialOffer.credentials?.get(index?:0)?.doctype?.let {
                        types.add(it)
                    }
                }else{
                    types = credentialOffer.credentials?.get(index?:0)?.types ?: ArrayList()
                }
            } catch (e: Exception) {
            }
        } catch (e: Exception) {

        }

        return types
    }


    /**
     * Get cryptographicSuits from issuer config
     *
     * @param issuerConfig
     * @param type
     * @return
     */
    override fun getCryptoFromIssuerConfig(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?
    ): ArrayList<String>? {
        var types: ArrayList<String> = ArrayList()
        val credentialOfferJsonString = Gson().toJson(issuerConfig)
        val jsonObject = JSONObject(credentialOfferJsonString)

        val credentialsSupported: Any = jsonObject.opt("credentials_supported") ?: return null
        when (credentialsSupported) {
            is JSONObject -> {
                try {
                    val credentialSupported = credentialsSupported.getJSONObject(type ?: "")
                    val cryptographicSuitsSupported =
                        credentialSupported.getJSONArray("cryptographic_suites_supported")
                    for (i in 0 until cryptographicSuitsSupported.length()) {
                        // Get each JSONObject from the JSONArray
                        val type: String = cryptographicSuitsSupported.getString(i)
                        types.add(type)
                    }
                } catch (e: Exception) {
                }
            }

            is JSONArray -> {
                try {
                    for (i in 0 until credentialsSupported.length()) {
                        val jsonObject: JSONObject = credentialsSupported.getJSONObject(i)

                        // Get the "types" JSONArray
                        val typesArray = jsonObject.getJSONArray("types")

                        // Check if the string is present in the "types" array
                        for (j in 0 until typesArray.length()) {
                            if (typesArray.getString(j) == type) {
                                val cryptographicSuitsSupported =
                                    jsonObject.getJSONArray("cryptographic_suites_supported")
                                for (i in 0 until cryptographicSuitsSupported.length()) {
                                    // Get each JSONObject from the JSONArray
                                    val type: String = cryptographicSuitsSupported.getString(i)
                                    types.add(type)
                                }
                                break
                            }
                        }
                    }
                } catch (e: Exception) {
                }
            }

            else -> {
                // Neither JSONObject nor JSONArray
                println("Child is neither JSONObject nor JSONArray")
            }
        }

        return types
    }

    override fun isCredentialMetaDataAvailable(
        issuerConfig: IssuerWellKnownConfiguration?,
        type: String?,
        version: Int?
    ): Boolean {
        try {
            val credentialOfferJsonString = Gson().toJson(issuerConfig)
            // Check if credentialOfferJsonString is null or empty
            if (credentialOfferJsonString.isNullOrEmpty()) {
                return false
            }
            val jsonObject = JSONObject(credentialOfferJsonString)

            val credentialsSupported: Any =
                jsonObject.opt("credentials_supported") ?: return false
            when (credentialsSupported) {
                is JSONObject -> {
                    try {
                        return credentialsSupported.has(type ?: "")
                    } catch (e: Exception) {
                        return false
                    }
                }
                is JSONArray -> {
                    for (i in 0 until credentialsSupported.length()) {
                        val item = credentialsSupported.optJSONObject(i) ?: continue

                        // First check "types" array
                        val typesArray = item.optJSONArray("types")
                        if (typesArray != null) {
                            if ((0 until typesArray.length()).any { typesArray.optString(it) == type }) {
                                return true
                            }
                        } else {
                            // Fallback: check "docType" string
                            val docType = item.optString("doctype", "")
                            if (docType.isNotEmpty() && docType == type) {
                                return true
                            }
                        }
                    }
                    return false
                }
            }
        } catch (e: Exception) {

        }
        return false
    }
}