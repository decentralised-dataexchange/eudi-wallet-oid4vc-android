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
import com.ewc.eudi_wallet_oidc_android.models.CredentialTypeDefinition
import com.ewc.eudi_wallet_oidc_android.models.Credentials
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.Jwt
import com.ewc.eudi_wallet_oidc_android.models.ProofV3
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
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.utils.ErrorHandler
import com.google.gson.Gson
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
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import retrofit2.Response
import java.util.Date
import java.util.UUID
import com.ewc.eudi_wallet_oidc_android.services.utils.ProofService
import com.google.gson.GsonBuilder
import okhttp3.ResponseBody

class IssueService : IssueServiceInterface {

    /**
     * To process the credential offer request
     *
     * @param data - will accept the full data which is scanned from the QR
     *     code or deep link The data can contain credential offer or
     *     credential offer uri
     * @return Credential Offer
     */
    override suspend fun resolveCredentialOffer(data: String?): WrappedCredentialOffer? {
        if (data.isNullOrBlank()) return null
        try {
            val uri = Uri.parse(data)
            val credentialOfferUri = uri.getQueryParameter("credential_offer_uri")
            if (!credentialOfferUri.isNullOrBlank()) {
                UrlUtils.validateUri(credentialOfferUri)
                val response =
                    ApiManager.api.getService()?.resolveCredentialOffer(credentialOfferUri)
                return if (response?.isSuccessful == true) {
                    WrappedCredentialOffer(
                        credentialOffer =  parseCredentialOffer(credentialOfferJson = response.body()?.string())
                    )

                } else {
                    WrappedCredentialOffer(
                        errorResponse = ErrorHandler.processError(response?.errorBody()?.string())
                    )
                }
            }

            val credentialOfferString = uri.getQueryParameter("credential_offer")
            if (!credentialOfferString.isNullOrBlank()) {
                return WrappedCredentialOffer(credentialOffer =  parseCredentialOffer(credentialOfferJson = credentialOfferString))
            }
            return WrappedCredentialOffer(credentialOffer = null, errorResponse = null)
        } catch (exc: UriValidationFailed) {
            return null
        }catch (e:Exception){
            Log.d("Exception", e.message.toString())
            return  null
        }
    }

    private fun parseCredentialOffer(credentialOfferJson: String?): CredentialOffer? {
        val gson = Gson()
        val credentialOfferV2Response = try {
            gson.fromJson(credentialOfferJson, CredentialOfferEwcV2::class.java)
        } catch (e: Exception) {
            null
        }
        if (credentialOfferV2Response?.credentialConfigurationIds == null) {
            val credentialOfferEbsiV1Response = try {
                gson.fromJson(credentialOfferJson, CredentialOfferEbsiV1::class.java)
            } catch (e: Exception) {
                null
            }
            return if (credentialOfferEbsiV1Response?.credentials == null) {
                val credentialOfferEwcV1Response = try {
                    gson.fromJson(credentialOfferJson, CredentialOfferEwcV1::class.java)
                } catch (e: Exception) {
                    null
                }
                if (credentialOfferEwcV1Response == null) {
                    null
                } else {
                    CredentialOffer(ewcV1 = credentialOfferEwcV1Response)
                }
            } else {
                credentialOfferEbsiV1Response?.let { CredentialOffer(ebsiV1 = it) }
            }
        } else {
            return CredentialOffer(ewcV2 = credentialOfferV2Response)
        }
    }

    /**
     * To process the authorisation request The authorisation request is to
     * grant access to the credential endpoint
     *
     * @param did - DID created for the issuance
     * @param subJwk - for singing the requests
     * @param credentialOffer - To build the authorisation request
     * @param codeVerifier - to build the authorisation request
     * @param authorisationEndPoint - to build the authorisation request
     * @return String - short-lived authorisation code
     */
    override suspend fun processAuthorisationRequest(
        did: String?,
        subJwk: JWK?,
        credentialOffer: CredentialOffer?,
        codeVerifier: String,
        authConfig: AuthorisationServerWellKnownConfiguration?,
        format: String?,
        docType: String?,
        issuerConfig: IssuerWellKnownConfiguration?,
        redirectUri: String?
    ): String? {
        val authorisationEndPoint =authConfig?.authorizationEndpoint
        val responseType = "code"
        val types = getTypesFromCredentialOffer(credentialOffer)
        val scope = if (format == "mso_mdoc") {
            "${types.firstOrNull() ?: ""} openid"
        } else {
            "openid"
        }
        val state = UUID.randomUUID().toString()
        val clientId = did
        val authorisationDetails = buildAuthorizationRequest(
            credentialOffer = credentialOffer,
            format = format,
            doctype = docType,
            issuerConfig = issuerConfig,
            version = credentialOffer?.version
        )
        val redirectURI = redirectUri ?: "openid://callback"
        val nonce = UUID.randomUUID().toString()

        val codeChallenge = CodeVerifierService().generateCodeChallenge(codeVerifier)
        val codeChallengeMethod = "S256"
        val clientMetadata = if (format == "mso_mdoc") "" else Gson().toJson(
            ClientMetaDataas(
                vpFormatsSupported = VpFormatsSupported(
                    jwtVp = Jwt(arrayListOf("ES256")), jwtVc = Jwt(arrayListOf("ES256"))
                ), responseTypesSupported = arrayListOf(
                    "vp_token", "id_token"
                ), authorizationEndpoint = redirectURI
            )
        )
        var response: Response<ResponseBody>?=null
        if (authConfig?.requirePushedAuthorizationRequests == true){

            val parResponse = try {
                ApiManager.api.getService()?.processParAuthorisationRequest(
                    authConfig.pushedAuthorizationRequestEndpoint ?: "",
                    mapOf(
                        "response_type" to responseType,
                        "scope" to scope.trim(),
                        "state" to state,
                        "client_id" to (clientId ?: ""),
                        "authorization_details" to authorisationDetails,
                        "redirect_uri" to redirectURI,
                        "nonce" to nonce,
                        "code_challenge" to (codeChallenge ?: ""),
                        "code_challenge_method" to codeChallengeMethod,
                        "client_metadata" to clientMetadata,
                        "issuer_state" to (credentialOffer?.grants?.authorizationCode?.issuerState ?: "")
                    ),
                )
            } catch (e: javax.net.ssl.SSLHandshakeException) {
                null
            }
            // Check if the PAR request was successful
            parResponse?.code()
            if (parResponse?.isSuccessful == true) {
                // Extract requestUri from the PAR response
                val requestUri = parResponse.body()?.requestUri ?: ""

                // Second API call: processAuthorisationRequest
                response = ApiManager.api.getService()?.processAuthorisationRequest(
                    authorisationEndPoint ?: "",
                    mapOf(
                        "client_id" to (clientId ?: ""),
                        "request_uri" to requestUri
                    )
                )
                if (response?.isSuccessful == true) {
                    val contentType = response.headers()["Content-Type"]

                    if (contentType?.contains("text/html") == true) {
                       return response.raw().request.url.toString()
                    }
                }
            }

        }
        else{

            response = ApiManager.api.getService()?.processAuthorisationRequest(
                authorisationEndPoint ?: "",
                mapOf(
                    "response_type" to responseType,
                    "scope" to scope.trim(),
                    "state" to state,
                    "client_id" to (clientId ?: ""),
                    "authorization_details" to authorisationDetails,
                    "redirect_uri" to (redirectURI ?: ""),
                    "nonce" to nonce,
                    "code_challenge" to (codeChallenge ?: ""),
                    "code_challenge_method" to codeChallengeMethod,
                    "client_metadata" to clientMetadata,
                    "issuer_state" to (credentialOffer?.grants?.authorizationCode?.issuerState ?: "")
                ),
            )
        }

        if (response?.code() == 502) {
            throw Exception("Unexpected error. Please try again.")
        }
        val location: String? = if (response?.code() == 302) {
            if (response.headers()["Location"]?.contains("error") == true || response.headers()["Location"]?.contains(
                    "error_description"
                ) == true
            ) {
                response.headers()["Location"]
            } else {
                response.headers()["Location"]
            }
        } else {
            null
        }

        return if (location == null){
            null
        } else if (Uri.parse(location).getQueryParameter("error") != null) {
            location
        } else if (Uri.parse(location).getQueryParameter("code") != null
            || Uri.parse(location).getQueryParameter("presentation_definition") != null
            || Uri.parse(location).getQueryParameter("presentation_definition_uri") != null
            || (Uri.parse(location).getQueryParameter("request_uri") != null &&
                    Uri.parse(location).getQueryParameter("response_type") == null &&
                    Uri.parse(location).getQueryParameter("state") == null)
        ) {
            location
        } else if (
            Uri.parse(location).getQueryParameter("response_type") == "id_token" &&
            Uri.parse(location).getQueryParameter("redirect_uri") != null
        ){
            processAuthorisationRequestUsingIdToken(
                did = did,
                authorisationEndPoint = authorisationEndPoint,
                location = location,
                subJwk = subJwk
            )
        }
        else if (!location.startsWith(redirectURI)) {
            location
        } else {
            processAuthorisationRequestUsingIdToken(
                did = did,
                authorisationEndPoint = authorisationEndPoint,
                location = location,
                subJwk = subJwk
            )
        }
    }

    private suspend fun processAuthorisationRequestUsingIdToken(
        did: String?,
        authorisationEndPoint: String?,
        location: String?,
        subJwk: JWK?
    ): String? {
        val claimsSet =
            JWTClaimsSet.Builder()
                .issueTime(Date())
                .expirationTime(Date(Date().time + 60000))
                .issuer(did)
                .subject(did)
                .audience( Uri.parse(location).getQueryParameter("client_id")?:authorisationEndPoint)
                .claim("nonce", Uri.parse(location).getQueryParameter("nonce"))
                .build()

        // Create JWT for ES256K alg
        val jwsHeader =
            JWSHeader.Builder(if (subJwk is OctetKeyPair) JWSAlgorithm.EdDSA else JWSAlgorithm.ES256)
                .type(JOSEObjectType.JWT)
                .keyID("$did#${did?.replace("did:key:", "")}")
                .build()

        val jwt = SignedJWT(
            jwsHeader, claimsSet
        )

        // Sign with private EC key
        jwt.sign(
            if (subJwk is OctetKeyPair) Ed25519Signer(subJwk as OctetKeyPair) else ECDSASigner(
                subJwk as ECKey
            )
        )

        val response = ApiManager.api.getService()?.sendIdTokenForCode(
            url = Uri.parse(location).getQueryParameter("redirect_uri") ?: "",
            idToken = jwt.serialize(),
            state = Uri.parse(location).getQueryParameter("state") ?: "",
            contentType = "application/x-www-form-urlencoded"
        )

        return if (response?.code() == 302) {
            response.headers()["Location"]
        } else {
            null
        }
    }

    private fun buildAuthorizationRequest(
        credentialOffer: CredentialOffer?,
        format: String?,
        doctype: String?
    ): String {
        val gson = Gson()
        var credentialDefinitionNeeded = false
        try {
            if (credentialOffer?.credentials?.get(0)?.trustFramework == null)
                credentialDefinitionNeeded = true

        } catch (e: Exception) {
            credentialDefinitionNeeded = true
        }
        if (format == "mso_mdoc" && doctype != null) {
            return gson.toJson(
                arrayListOf(
                    AuthorizationDetails(
                        format = format,
                        doctype = doctype,
                        locations = arrayListOf(credentialOffer?.credentialIssuer ?: "")
                    )
                )
            )
        } else {
            if (credentialDefinitionNeeded) {
                return gson.toJson(
                    arrayListOf(
                        AuthorizationDetails(
                            format = format,
                            locations = arrayListOf(credentialOffer?.credentialIssuer ?: ""),
                            credentialDefinition = CredentialTypeDefinition(
                                type = getTypesFromCredentialOffer(credentialOffer)
                            )
                        )
                    )
                )

            } else {
                return gson.toJson(
                    arrayListOf(
                        AuthorizationDetails(
                            format = format,
                            types = getTypesFromCredentialOffer(credentialOffer),
                            locations = arrayListOf(credentialOffer?.credentialIssuer ?: "")
                        )
                    )
                )
            }
        }

    }


    private fun buildAuthorizationRequest(
        credentialOffer: CredentialOffer?,
        format: String?,
        doctype: String?,
        version: Int? = 2,
        issuerConfig: IssuerWellKnownConfiguration?
    ): String {
        val gson = Gson()

        when (version) {
            1 -> {
                return buildAuthorizationRequest(
                    credentialOffer = credentialOffer,
                    format = format,
                    doctype = doctype
                )
            }
            else -> {
                val authorizationDetailList: ArrayList<AuthorizationDetails> = ArrayList()
                for (credential in credentialOffer?.credentials ?: arrayListOf()) {
                    authorizationDetailList.add(AuthorizationDetails(
                        credentialConfigurationId = credential.types?.firstOrNull(),
                    ))
                }
                return gson.toJson(authorizationDetailList)
            }
        }
//        if (format == "mso_mdoc" && doctype != null) {
//            return gson.toJson(
//                arrayListOf(
//                    AuthorizationDetails(
//                        type = "openid_credential",
//                        doctype = doctype,
//                        credentialConfigurationId = credentialConfigurationId,
//                        locations = arrayListOf(credentialOffer?.credentialIssuer ?: "")
//                    )
//                )
//            )
//        } else {
//            when (version) {
//                1 -> {
//                    return buildAuthorizationRequest(
//                        credentialOffer = credentialOffer,
//                        format = format,
//                        doctype = doctype
//                    )
//                }
//
//                else -> {
//                    return gson.toJson(
//                        arrayListOf(
//                            AuthorizationDetails(
//                                format = null ,
//                                credentialConfigurationId = credentialConfigurationId,
//                            )
//                        )
//                    )
//                }
//            }
//        }
    }

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
        clientAssertion: String?,
        walletUnitAttestationJWT: String? ,
        walletUnitProofOfPossession: String?,
        redirectUri: String?
    ): WrappedTokenResponse? {
        val redirectURI = redirectUri ?: "openid://callback"
        val headers = mutableMapOf<String, String>().apply {
            if (!walletUnitAttestationJWT.isNullOrEmpty()) {
                this["OAuth-Client-Attestation"] = walletUnitAttestationJWT
            }
            if (!walletUnitProofOfPossession.isNullOrEmpty()) {
                this["OAuth-Client-Attestation-PoP"] = walletUnitProofOfPossession
            }
        }
        val response = ApiManager.api.getService()?.getAccessTokenFromCode(
            tokenEndPoint ?: "",
            if (isPreAuthorisedCodeFlow == true) {
                // Map for pre-authorized code flow
                mutableMapOf(
                    "grant_type" to "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    "pre-authorized_code" to (code ?: "")
                ).apply {
                    if (version == 1) {
                        this["user_pin"] = userPin ?: ""
                    } else {
                        this["tx_code"] = userPin ?: ""
                    }
                }
            } else {
                // Map for authorization code flow
                mutableMapOf(
                    "grant_type" to "authorization_code",
                    "code" to (code ?: ""),
                    "client_id" to (did ?: ""),
                    "code_verifier" to (codeVerifier ?: ""),
                    "redirect_uri" to (redirectURI ?: "")
                ).apply {
                    if (clientAssertion != null) {
                        this["client_assertion"] = clientAssertion ?: ""
                        this["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    }
                }
            },
            headers
        )

        val tokenResponse = when {
            response?.isSuccessful == true -> {
                val lpid = response.headers()["legal-pid-attestation"]
                val lpidPoP = response.headers()["legal-pid-attestation-pop"]
                WrappedTokenResponse(
                    tokenResponse = response.body(),
                    legalPidAttestation = lpid,
                    legalPidAttestationPoP = lpidPoP
                )
            }

            (response?.code() ?: 0) >= 400 -> {
                try {
                    WrappedTokenResponse(
                        errorResponse = ErrorHandler.processError(response?.errorBody()?.string())
                    )
                } catch (e: Exception) {
                    null
                }
            }

            else -> {
                null
            }
        }
        return tokenResponse
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
        // API call
        val response = ApiManager.api.getService()?.getCredential(
            issuerConfig?.credentialEndpoint ?: "",
            "application/json",
            "Bearer $accessToken",
            body
        )

        val credentialResponse = when {
            (response?.code() ?: 0) >= 400 -> {
                try {
                    WrappedCredentialResponse(
                        errorResponse = ErrorHandler.processError(response?.errorBody()?.string())
                    )
                } catch (e: Exception) {
                    null
                }
            }

            response?.isSuccessful == true -> {
                WrappedCredentialResponse(
                    credentialResponse = response.body()
                )
            }

            else -> {
                null
            }
        }

        return credentialResponse
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
        index: Int
    ): WrappedCredentialResponse? {

        val jwt = ProofService().createProof(did, subJwk, nonce , issuerConfig,credentialOffer)
        if (jwt == null) {
            Log.e("IssueService", "Failed to create proof for credential request")
            return null
        }

            val request: CredentialRequest = if (authorizationDetail != null && authorizationDetail.type == "openid_credential" && !authorizationDetail.credentialIdentifiers.isNullOrEmpty()) {
                CredentialRequest(
                    credentialIdentifier = authorizationDetail.credentialIdentifiers.firstOrNull(),
                    proof = ProofV3(jwt = jwt, proofType = "jwt"),
                )
            }  else if (authorizationDetail !=null && authorizationDetail.type == "openid_credential" && issuerConfig?.nonceEndpoint!=null && !authorizationDetail.credentialConfigurationId.isNullOrBlank()) {
                CredentialRequest(
                    credentialConfigurationId = authorizationDetail.credentialConfigurationId,
                    proof = ProofV3(jwt = jwt, proofType = "jwt"),
                )
            } else if (accessToken?.cNonce==null && issuerConfig?.nonceEndpoint!=null && accessToken?.authorizationDetails.isNullOrEmpty()){
                CredentialRequest(
                    credentialConfigurationId = credentialOffer?.credentials?.get(index)?.types?.firstOrNull(),
                    proof = ProofV3(jwt = jwt, proofType = "jwt"),
                    )
            } else {
                val doctype = fetchDoctype(index,credentialOffer,issuerConfig)
                var types: ArrayList<String> = ArrayList()
                var format: String? = null
                try {
                    types = credentialOffer?.credentials?.get(index)?.types ?: ArrayList()
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

            val response = ApiManager.api.getService()?.getCredential(
                issuerConfig?.credentialEndpoint ?: "",
                "application/json",
                "Bearer ${accessToken?.accessToken}",
                request
            )
            val credentialResponse = when {
                (response?.code() ?: 0) >= 400 -> {
                    try {
                        WrappedCredentialResponse(
                            errorResponse = ErrorHandler.processError(response?.errorBody()?.string())
                        )
                    } catch (e: Exception) {
                        null
                    }
                }

                response?.isSuccessful == true -> {
                    WrappedCredentialResponse(
                        credentialResponse = response.body()
                    )
                }

                else -> {
                    null
                }
            }
            return credentialResponse
    }

    private fun fetchDoctype(
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

    private fun buildCredentialRequest(
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
        deferredCredentialEndPoint: String?
    ): WrappedCredentialResponse? {
        val response = ApiManager.api.getService()?.getDifferedCredential(
            deferredCredentialEndPoint ?: "",
            "Bearer $acceptanceToken",
            CredentialRequest() // empty object
        )

        return if (response?.isSuccessful == true
            && (response.body()?.credential != null || !response.body()?.credentials.isNullOrEmpty())
        ) {
            WrappedCredentialResponse(credentialResponse = response.body())
        } else {
            null
        }
    }

    override suspend fun processDeferredCredentialRequestV2(
        transactionId: String?,
        accessToken: String?,
        deferredCredentialEndPoint: String?
    ): WrappedCredentialResponse? {
        val response = ApiManager.api.getService()?.getDifferedCredentialV2(
            deferredCredentialEndPoint ?: "",
            "Bearer $accessToken",
            DeferredCredentialRequestV2(transactionId)
        )

        return if (response?.isSuccessful == true
            && (response.body()?.credential != null || !response.body()?.credentials.isNullOrEmpty())
        ) {
            WrappedCredentialResponse(credentialResponse = response.body())
        } else {
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