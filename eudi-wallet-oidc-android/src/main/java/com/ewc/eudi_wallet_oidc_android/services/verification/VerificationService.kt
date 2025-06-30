package com.ewc.eudi_wallet_oidc_android.services.verification

import android.net.Uri
import android.util.Base64
import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.ClientMetaDetails
import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.models.DescriptorMap
import com.ewc.eudi_wallet_oidc_android.models.DescriptorMapMdoc
import com.ewc.eudi_wallet_oidc_android.models.Document
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.InputDescriptors
import com.ewc.eudi_wallet_oidc_android.models.IssuerSigned
import com.ewc.eudi_wallet_oidc_android.models.PathNested
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.PresentationSubmission
import com.ewc.eudi_wallet_oidc_android.models.PresentationSubmissionMdoc
import com.ewc.eudi_wallet_oidc_android.models.VPTokenResponse
import com.ewc.eudi_wallet_oidc_android.models.VpToken
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.WrappedVpTokenResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.IssueService
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.sdjwt.SDJWTService
import com.ewc.eudi_wallet_oidc_android.services.utils.CborUtils
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.isValidJWT
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.parseJWTForPayload
import com.ewc.eudi_wallet_oidc_android.services.verification.clientIdSchemeHandling.ClientIdSchemeRequestHandler
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletAttestationUtil
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletAttestationUtil.generateHash
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse.AuthorisationResponseHandler
import com.github.decentraliseddataexchange.presentationexchangesdk.PresentationExchange
import com.github.decentraliseddataexchange.presentationexchangesdk.models.MatchedCredential
import com.google.gson.Gson
import com.google.gson.internal.LinkedTreeMap
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.util.Date
import java.util.UUID
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.nio.charset.StandardCharsets

class VerificationService : VerificationServiceInterface {


    /**
     * Authorisation requests can be presented to the wallet by verifying in two ways:
     * 1) by value
     * 2) by reference as defined in JWT-Secured Authorization Request (JAR) via use of request_uri.
     *      The custom URL scheme for authorisation requests is openid4vp://.
     *
     * @param data - will accept the full data which is scanned from the QR code or deep link
     *
     * @return PresentationRequest
     */
    override suspend fun processAuthorisationRequest(data: String?): WrappedPresentationRequest? {
        if (data.isNullOrBlank())
            return null

        val gson = Gson()

        val clientId = Uri.parse(data).getQueryParameter("client_id")
        val state = Uri.parse(data).getQueryParameter("state")
        val redirectUri = Uri.parse(data).getQueryParameter("redirect_uri")
        val nonce = Uri.parse(data).getQueryParameter("nonce")
        val presentationDefinition =
            Uri.parse(data).getQueryParameter("presentation_definition")
        val presentationDefinitionUri =
            Uri.parse(data).getQueryParameter("presentation_definition_uri")
        val responseType = Uri.parse(data).getQueryParameter("response_type")
        val scope = Uri.parse(data).getQueryParameter("scope")
        val requestUri = Uri.parse(data).getQueryParameter("request_uri")
        val responseUri = Uri.parse(data).getQueryParameter("response_uri")
        val responseMode = Uri.parse(data).getQueryParameter("response_mode")
        val clientMetadataUri = Uri.parse(data).getQueryParameter("client_metadata_uri")
        val clientMetadataJson = Uri.parse(data).getQueryParameter("client_metadata")
        val clientIdScheme = Uri.parse(data).getQueryParameter("client_id_scheme")
        val clientMetadetails: ClientMetaDetails? = if (!clientMetadataJson.isNullOrBlank()) {
            gson.fromJson(clientMetadataJson, ClientMetaDetails::class.java)
        } else {
            null
        }
        val request = Uri.parse(data).getQueryParameter("request")
        val dcqlQueryJson = Uri.parse(data).getQueryParameter("dcql_query")
        val dcqlQuery: DCQL? = dcqlQueryJson
            ?.takeIf { it.isNotBlank() }
            ?.let { gson.fromJson(it, DCQL::class.java) }

        if (presentationDefinition != null || presentationDefinitionUri != null) {
            val presentationRequest = PresentationRequest(
                clientId = clientId,
                state = state,
                redirectUri = redirectUri,
                nonce = nonce,
                presentationDefinition = presentationDefinition,
                presentationDefinitionUri = presentationDefinitionUri,
                responseMode = responseMode,
                responseType = responseType,
                scope = scope,
                requestUri = requestUri,
                responseUri = responseUri,
                clientMetaDetails = clientMetadetails,
                clientIdScheme = clientIdScheme,
                request = request,
                dcqlQuery = dcqlQuery
            )
            if (presentationDefinition.isNullOrBlank() && !presentationDefinitionUri.isNullOrBlank()) {
                val resolvedPresentationDefinition =
                    getPresentationDefinitionFromDefinitionUri(presentationDefinitionUri)
                presentationRequest.presentationDefinition = resolvedPresentationDefinition
            }
            if (clientMetadataJson.isNullOrBlank() && !clientMetadataUri.isNullOrBlank()) {
                val resolvedClientMetaData =
                    getClientMetaDataFromClientMetaDataUri(clientMetadataUri)
                presentationRequest.clientMetaDetails = resolvedClientMetaData
            }
            return WrappedPresentationRequest(
                presentationRequest = presentationRequest,
                errorResponse = null
            )

        }
        else if (!requestUri.isNullOrBlank() || !responseUri.isNullOrBlank()) {
            try {

                val response =
                    ApiManager.api.getService()
                        ?.getPresentationDefinitionFromRequestUri(requestUri ?: responseUri ?: "")
                if (response?.isSuccessful == true) {
                    val responseString = response.body()?.string()

                    // Check if responseString is null or empty
                    if (responseString.isNullOrBlank()) {
                        return WrappedPresentationRequest(
                            presentationRequest = null,
                            errorResponse = ErrorResponse(
                                error = null,
                                errorDescription = "Response string is null or empty."
                            )
                        )
                    }

                    // Try to parse the response as JSON
                    val json: PresentationRequest? = try {
                        gson.fromJson(responseString, PresentationRequest::class.java)
                    } catch (e: Exception) {
                        null // If JSON parsing fails, return null and proceed with JWT validation
                    }

                    if (json != null) {
                        val updatedPresentationRequest =
                            updatePresentationRequest(json, responseString)
                        return processPresentationRequest(updatedPresentationRequest)
                    }
                    else{
                        if (isValidJWT(responseString ?: "")) {
                            val payload = parseJWTForPayload(responseString ?: "{}")
                            val jwtJson = gson.fromJson(payload, PresentationRequest::class.java)
                            val updatedPresentationRequest =
                                updatePresentationRequest(jwtJson, responseString)
                            return processPresentationRequest(updatedPresentationRequest)

                        } else {
                           return WrappedPresentationRequest(
                                presentationRequest = null,
                                errorResponse = ErrorResponse(
                                    error = null,
                                    errorDescription = "Invalid Request"
                                )
                            )
                        }
                    }
                } else {
                    return null
                }
            } catch (e: Exception) {
                return WrappedPresentationRequest(
                    presentationRequest = null,
                    errorResponse = ErrorResponse(
                        error = null,
                        errorDescription = e.message.toString()
                    )
                )
            }

        } else if (isValidJWT(data)) {
            val json = gson.fromJson(
                parseJWTForPayload(data),
                PresentationRequest::class.java
            )
            val updatedPresentationRequest = updatePresentationRequest(json, data)
            return processPresentationRequest(updatedPresentationRequest)

        } else {
            return null
        }
    }

    fun updatePresentationRequest(
        presentationRequest: PresentationRequest?,
        responseString: String?
    ): PresentationRequest? {
        if (presentationRequest == null) return null
        presentationRequest.request = presentationRequest.request ?: responseString
        if (presentationRequest.dcqlQuery != null) {
            presentationRequest.presentationDefinition =
                getPresentationDefinitionFromDcql(presentationRequest)
        }
        return presentationRequest
    }

    private fun getPresentationDefinitionFromDcql(json: PresentationRequest): PresentationDefinition {
        return DcqlToPresentationDefinition().convertToOID4VP(
            json.dcqlQuery
        )
    }

    private suspend fun processPresentationRequest(
        json: PresentationRequest?
    ): WrappedPresentationRequest {
        if (json?.presentationDefinition == null && !json?.presentationDefinitionUri.isNullOrBlank()) {
            val resolvedPresentationDefinition =
                getPresentationDefinitionFromDefinitionUri(json.presentationDefinitionUri)
            json.presentationDefinition = resolvedPresentationDefinition
        }
        if (json?.clientMetaDetails == null && !json?.clientMetadataUri.isNullOrBlank()) {
            val resolvedClientMetaDetails =
                getClientMetaDataFromClientMetaDataUri(json.clientMetadataUri)
            json.clientMetaDetails = resolvedClientMetaDetails
        }

        return validatePresentationRequest(
            WrappedPresentationRequest(
                presentationRequest = json
            )
        )
    }

    private suspend fun validatePresentationRequest(
        presentationRequest: WrappedPresentationRequest
    ): WrappedPresentationRequest {

        val wrappedPresentationRequest =
            ClientIdSchemeRequestHandler().handle(presentationRequest)
        return wrappedPresentationRequest
    }

    private suspend fun processJwtFromRedirectUri(redirectUri: String): String? =
        withContext(Dispatchers.IO) {
            // Fetch JWT from the redirect URI
            val jwt = fetchJwtFromUri(redirectUri)
            jwt?.let {
                // Decode the JWT to extract the payload
                val decodedPayload = decodeJwtPayload(it)
                decodedPayload?.let { payload ->
                    // Parse JSON payload and retrieve fields
                    val jsonPayload = JSONObject(payload)
                    val clientId = jsonPayload.optString("client_id")
                    val clientIdScheme = jsonPayload.optString("client_id_scheme")

                    // Use client_id and client_id_scheme as needed
                    println("Client ID: $clientId")
                    println("Client ID Scheme: $clientIdScheme")

                    return@withContext payload // Return payload or process further as needed
                }
            }
            return@withContext null
        }

    private fun fetchJwtFromUri(uri: String): String? {
        try {
            val url = URL(uri)
            val connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "GET"

            if (connection.responseCode == HttpURLConnection.HTTP_OK) {
                val reader = BufferedReader(InputStreamReader(connection.inputStream))
                val jwt = reader.use { it.readText() }
                connection.disconnect()
                return jwt
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    private fun decodeJwtPayload(jwt: String): String? {
        val parts = jwt.split(".")
        return if (parts.size == 3) {
            val payload = parts[1]
            val decodedBytes = Base64.decode(payload, Base64.URL_SAFE)
            String(decodedBytes, StandardCharsets.UTF_8)
        } else {
            null
        }
    }

    private suspend fun getPresentationDefinitionFromDefinitionUri(presentationDefinitionUri: String?): PresentationDefinition? {
        if (presentationDefinitionUri.isNullOrBlank())
            return null

        val response =
            ApiManager.api.getService()
                ?.resolveUrl(presentationDefinitionUri)
        if (response?.isSuccessful == true) {
            val contentType = response.headers()["Content-Type"]
            val responseString = response.body()?.string()
            val gson = Gson()
            if (contentType?.contains("application/json") == true) {
                val json = gson.fromJson(
                    responseString,
                    PresentationDefinition::class.java
                )
                return json
            } else {
                if (isValidJWT(responseString ?: "")) {
                    val json = gson.fromJson(
                        parseJWTForPayload(responseString ?: "{}"),
                        PresentationDefinition::class.java
                    )
                    return json
                } else {
                    val json = gson.fromJson(
                        responseString ?: "{}",
                        PresentationDefinition::class.java
                    )
                    return json
                }
            }
        } else {
            return null
        }
    }

    private suspend fun getClientMetaDataFromClientMetaDataUri(clientMetadataUri: String?): ClientMetaDetails? {
        if (clientMetadataUri.isNullOrBlank())
            return null

        val response =
            ApiManager.api.getService()?.resolveUrl(clientMetadataUri)
        if (response?.isSuccessful == true) {
            try {
                val contentType = response.headers()["Content-Type"]
                val responseString = response.body()?.string()
                val gson = Gson()
                if (contentType?.contains("application/json") == true) {
                    val json = gson.fromJson(
                        responseString,
                        ClientMetaDetails::class.java
                    )
                    return json
                } else {
                    if (isValidJWT(responseString ?: "")) {
                        val json = gson.fromJson(
                            parseJWTForPayload(responseString ?: "{}"),
                            ClientMetaDetails::class.java
                        )
                        return json
                    } else {
                        val json = gson.fromJson(
                            responseString ?: "{}",
                            ClientMetaDetails::class.java
                        )
                        return json
                    }
                }
            } catch (e: Exception) {
                return null
            }
        } else {
            return null
        }
    }

    /**
     * Authorisation response is sent by constructing the vp_token and presentation_submission values.
     */
    override suspend fun sendVPToken(
        did: String?,
        subJwk: ECKey?,
        presentationRequest: PresentationRequest,
        credentialList: List<String>
    ): String? {
        val iat = Date()
        val jti = "urn:uuid:${UUID.randomUUID()}"
        val claimsSet = JWTClaimsSet.Builder()
            .audience(presentationRequest.clientId)
            .issueTime(iat)
            .expirationTime(Date(iat.time + 600000))
            .issuer(did)
            .jwtID(jti)
            .notBeforeTime(iat)
            .claim("nonce", presentationRequest.nonce)
            .subject(did)
            .claim(
                "vp", com.nimbusds.jose.shaded.json.JSONObject(
                    hashMapOf(
                        "@context" to listOf("https://www.w3.org/2018/credentials/v1"),
                        "holder" to did,
                        "id" to jti,
                        "type" to listOf("VerifiablePresentation"),
                        "verifiableCredential" to credentialList
                    )
                )
            ).build()

        // Create JWT for ES256K alg
        val jwsHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("JWT"))
            .keyID("$did#${did?.replace("did:key:", "")}")
            .jwk(subJwk?.toPublicJWK())
            .build()

        val jwt = SignedJWT(
            jwsHeader,
            claimsSet
        )
        // Sign with private EC key
        jwt.sign(ECDSASigner(subJwk))

        val response = ApiManager.api.getService()?.sendVPToken(
            presentationRequest.responseUri ?: presentationRequest.redirectUri ?: "",
            mapOf(
                "vp_token" to jwt.serialize(),
                "presentation_submission" to Gson().toJson(
                    createPresentationSubmission(
                        presentationRequest
                    )
                ),
                "state" to (presentationRequest.state ?: "")
            )
        )

        return if (response?.code() == 302 || response?.code() == 200) {
            response.headers()["Location"] ?: "https://tid-wallet-poc.azurewebsites.net?code=1"
        } else {
            null
        }
    }

    /**
     * Send VP token
     *
     * @param did
     * @param subJwk
     * @param presentationRequest
     * @param credentialList
     * @return
     */
    override suspend fun sendVPToken(
        did: String?,
        subJwk: JWK?,
        presentationRequest: PresentationRequest,
        credentialList: List<String>,
        walletUnitAttestationJWT: String?,
        walletUnitProofOfPossession: String?,
    ): WrappedVpTokenResponse? {

        val responseUri = presentationRequest.responseUri ?: presentationRequest.redirectUri
        if (responseUri.isNullOrEmpty() || !isHostReachable(responseUri)) {
            return WrappedVpTokenResponse(
                errorResponse = ErrorResponse(
                    error = null,
                    errorDescription = "Unable to resolve host: $responseUri"
                )
            )
        }
        val headers = mutableMapOf<String, String>().apply {
            if (!walletUnitAttestationJWT.isNullOrEmpty()) {
                this["OAuth-Client-Attestation"] = walletUnitAttestationJWT
            }
            if (!walletUnitProofOfPossession.isNullOrEmpty()) {
                this["OAuth-Client-Attestation-PoP"] = walletUnitProofOfPossession
            }
        }

        val presentationDefinition =
            processPresentationDefinition(presentationRequest.presentationDefinition)
        val formatMap = presentationDefinition.format?.takeIf { it.isNotEmpty() }
            ?: presentationDefinition.inputDescriptors
                ?.flatMap { it.format?.toList() ?: emptyList() }
                ?.toMap()

        val vpToken = if (formatMap?.containsKey("mso_mdoc") == true) {
            mdocVpToken(credentialList, presentationRequest)
        } else {
            processToken(presentationRequest, did, credentialList, subJwk)
        }
        val presentationSubmission = if (formatMap?.containsKey("mso_mdoc") == true) {
            createMdocPresentationSubmission(
                presentationRequest
            )
        } else {
            createPresentationSubmission(
                presentationRequest
            )
        }


        val response = ApiManager.api.getService()?.sendVPToken(
            presentationRequest.responseUri ?: presentationRequest.redirectUri ?: "",
            mapOf(
                "vp_token" to vpToken,
                "presentation_submission" to Gson().toJson(
                    presentationSubmission
                ),
                "state" to (presentationRequest.state ?: "")
            ),
            headers
        )

        val tokenResponse = when {
            response?.code() == 200 -> {
                val redirectUri = response.body()?.string()
                val gson = Gson()
                try {
                    val vpTokenResponse =
                        gson.fromJson(redirectUri, VPTokenResponse::class.java)
                    return WrappedVpTokenResponse(
                        vpTokenResponse = VPTokenResponse(
                            location = vpTokenResponse.redirectUri
                                ?: "https://www.example.com?code=1"
                        )
                    )
                } catch (e: Exception) {
                    return WrappedVpTokenResponse(
                        vpTokenResponse = VPTokenResponse(
                            location = "https://www.example.com?code=1"
                        )
                    )
                }
            }

            response?.code() == 302 || response?.code() == 200 -> {
                val locationHeader = response.headers()["Location"]
                if (locationHeader?.contains("error=") == true) {
                    // Parse the error from the location header
                    val errorParams = locationHeader.substringAfter("?").split("&").associate {
                        val (key, value) = it.split("=")
                        key to value
                    }

                    WrappedVpTokenResponse(
                        errorResponse = ErrorResponse(
                            error = when (errorParams["error"]) {
                                "invalid_request" -> 400
                                else -> null
                            },
                            errorDescription = errorParams["error_description"]
                        )
                    )
                } else {
                    WrappedVpTokenResponse(
                        vpTokenResponse = VPTokenResponse(
                            location = locationHeader ?: "https://www.example.com?code=1"
                        )
                    )
                }

            }

            (response?.code() ?: 0) >= 400 -> {
                WrappedVpTokenResponse(
                    errorResponse = IssueService().processError(response?.errorBody()?.string())
                )
            }

            else -> {
                null
            }
        }
        return tokenResponse
    }

    override suspend fun processAndSendAuthorisationResponse(
        did: String?,
        subJwk: JWK?,
        presentationRequest: PresentationRequest,
        credentialList: List<String>?,
        walletUnitAttestationJWT: String?,
        walletUnitProofOfPossession: String?,
    ): WrappedVpTokenResponse {
        val headers = mutableMapOf<String, String>().apply {
            if (!walletUnitAttestationJWT.isNullOrEmpty()) {
                this["OAuth-Client-Attestation"] = walletUnitAttestationJWT
            }
            if (!walletUnitProofOfPossession.isNullOrEmpty()) {
                this["OAuth-Client-Attestation-PoP"] = walletUnitProofOfPossession
            }
        }
        try {
            val params =
                AuthorisationResponseHandler().prepareAuthorisationResponse(
                    presentationRequest = presentationRequest,
                    credentialList = credentialList,
                    did = did,
                    jwk = subJwk
                )
            Log.d("Params value:",params.toString())
            val response = ApiManager.api.getService()?.sendVPToken(
                presentationRequest.responseUri ?: presentationRequest.redirectUri ?: "",
                params,
                headers
            )

            val tokenResponse = when {
                response?.code() == 200 -> {
                    val redirectUri = response.body()?.string()
                    val gson = Gson()
                    try {
                        val vpTokenResponse =
                            gson.fromJson(redirectUri, VPTokenResponse::class.java)
                        return WrappedVpTokenResponse(
                            vpTokenResponse = VPTokenResponse(
                                location = vpTokenResponse.redirectUri
                                    ?: "https://www.example.com?code=1"
                            )
                        )
                    } catch (e: Exception) {
                        return WrappedVpTokenResponse(
                            vpTokenResponse = VPTokenResponse(
                                location = "https://www.example.com?code=1"
                            )
                        )
                    }
                }

                response?.code() == 204 -> {
                    try {
                        val urlValue = response.raw().request.url.toString()

                        if (urlValue.isNullOrEmpty()) {
                            return WrappedVpTokenResponse(
                                vpTokenResponse = null,
                                errorResponse = ErrorResponse(
                                    error = null,
                                    errorDescription = "The response URL is missing or empty"
                                )
                            )
                        }

                        return WrappedVpTokenResponse(
                            vpTokenResponse = VPTokenResponse(location = urlValue)
                        )
                    } catch (e: Exception) {
                        e.printStackTrace() // Log the exception for debugging
                        return WrappedVpTokenResponse(
                            vpTokenResponse = null,
                            errorResponse = ErrorResponse(
                                error = null,
                                errorDescription = "An unexpected error occurred: ${e.message}"
                            )
                        )
                    }
                }


                response?.code() == 302 || response?.code() == 200 -> {
                    val locationHeader = response.headers()["Location"]
                    if (locationHeader?.contains("error=") == true) {
                        // Parse the error from the location header
                        val errorParams = locationHeader.substringAfter("?").split("&").associate {
                            val (key, value) = it.split("=")
                            key to value
                        }

                        WrappedVpTokenResponse(
                            errorResponse = ErrorResponse(
                                error = when (errorParams["error"]) {
                                    "invalid_request" -> 400
                                    else -> null
                                },
                                errorDescription = errorParams["error_description"]
                            )
                        )
                    } else {
                        WrappedVpTokenResponse(
                            vpTokenResponse = VPTokenResponse(
                                location = locationHeader ?: "https://www.example.com?code=1"
                            )
                        )
                    }

                }

                (response?.code() ?: 0) >= 400 -> {
                    val errorBody = response?.errorBody()?.string()
                    val errorMessage =
                        errorBody?.takeIf { it.isNotBlank() } ?: "An unexpected error occurred"
                    WrappedVpTokenResponse(
                        errorResponse = ErrorResponse(
                            error = response?.code(),
                            errorDescription = errorMessage
                        )
                    )
                }


                else -> WrappedVpTokenResponse(
                    errorResponse = ErrorResponse(
                        error = response?.code(),
                        errorDescription = "An unexpected error occurred"
                    )
                )
            }
            return tokenResponse
        } catch (e: Exception) {
            return WrappedVpTokenResponse(
                vpTokenResponse = null,
                errorResponse = ErrorResponse(error = null, errorDescription = e.message.toString())
            )
        }


    }

    private fun isHostReachable(url: String?): Boolean {
        return try {
            // Extract the hostname from the URL
            val host = URL(url).host
            // Check if the host can be resolved
            InetAddress.getByName(host) != null
        } catch (e: Exception) {
            false
        }
    }

    private fun processToken(
        presentationRequest: PresentationRequest,
        did: String?,
        credentialList: List<String>? = null,
        subJwk: JWK?,
    ): String {
        val updatedCredentialList: MutableList<String> = mutableListOf()
        val iat = Date()
        val jti = "urn:uuid:${UUID.randomUUID()}"

        credentialList?.let { credentials ->
            for (credential in credentials) {
                try {
                    // Parse the JWT
                    val jwt: JWT = JWTParser.parse(credential)

                    // Get the payload as a JWTClaimsSet
                    val claimsSet = jwt.jwtClaimsSet
                    // Check for the presence of the "vct" parameter
                    if (claimsSet.getStringClaim("vct") != null) {
                        Log.d("processToken:", "SDJWT detected")

                        val claims = mutableMapOf<String, Any>()
                        Log.d(
                            "processToken:",
                            "transaction data = ${presentationRequest.transactionDdata}"
                        )
                        if (presentationRequest.transactionDdata?.isNotEmpty() == true) {
                            val transactionDataItem =
                                presentationRequest.transactionDdata?.getOrNull(0)
                            val hash = generateHash(transactionDataItem ?: "")
                            Log.d("processToken:", "transactionDataItem has added:${hash}")
                            if (transactionDataItem != null) {
                                claims["transaction_data_hashes"] = listOf(hash)
                                claims["transaction_data_hashes_alg"] = "sha-256"
                            }
                        } else {
                            Log.d("processToken:", "transaction data not added to claims")
                        }
                        val tempCredenital = "$credential${if (credential.endsWith("~")) "" else "~"}"
                        val keyBindingResponse = WalletAttestationUtil.createKeyBindingJWT(
                            aud = presentationRequest.clientId,
                            credential = tempCredenital,
                            subJwk = subJwk,
                            claims = if (claims.isNotEmpty()) claims else null,
                            nonce = presentationRequest?.nonce
                        )

                        Log.d("ProcessToken:", "keyBindingResponse $keyBindingResponse")
                        if (keyBindingResponse != null) {
                            // Append "~" only if it's not present at the end of the credential, then append keyBindingResponse
                            val updatedCredential =
                                "$tempCredenital$keyBindingResponse"


                            // Add the updated credential to the list
                            updatedCredentialList.add(updatedCredential)
                        } else {
                            Log.d("ProcessToken:", "keyBindingResponse is null")

                        }


                    } else {
                        Log.d("processToken:", "JWT detected")
                        updatedCredentialList.add(credential)

                    }

                } catch (e: Exception) {
                    Log.d("processToken:", "${e.message}")
                }
            }
        }

        val claimsSet = when (presentationRequest.responseType) {
            "vp_token" -> {
                Log.d("processToken:", "updatedCredentialList: ${updatedCredentialList.size}")
                JWTClaimsSet.Builder()
                    .audience(presentationRequest.clientId)
                    .issueTime(iat)
                    .expirationTime(Date(iat.time + 600000))
                    .issuer(did)
                    .jwtID(jti)
                    .notBeforeTime(iat)
                    .claim("nonce", presentationRequest.nonce)
                    .subject(did)
                    .claim(
                        "vp", com.nimbusds.jose.shaded.json.JSONObject(
                            hashMapOf(
                                "@context" to listOf("https://www.w3.org/2018/credentials/v1"),
                                "holder" to did,
                                "id" to jti,
                                "type" to listOf("VerifiablePresentation"),
                                "verifiableCredential" to updatedCredentialList
                            )
                        )
                    )
                    .build()
            }

            "id_token" -> {
                JWTClaimsSet.Builder()
                    .issuer(did)
                    .subject(did)
                    .audience(
                        presentationRequest.clientId
                            ?: "https://api-conformance.ebsi.eu/conformance/v3/auth-mock"
                    )
                    .expirationTime(Date(iat.time + 600000))
                    .issueTime(iat)
                    .claim("nonce", presentationRequest.nonce)
                    .build()
            }

            else -> {
                return ""
            }
        }
        Log.d("processToken:", "claimsSet value = ${claimsSet.toJSONObject()}")

        // Create JWT for ES256K alg
        val jwsHeader =
            JWSHeader.Builder(
                if (subJwk is OctetKeyPair)
                    JWSAlgorithm.EdDSA
                else
                    JWSAlgorithm.ES256
            )
                .type(JOSEObjectType("JWT"))
                .keyID("$did#${did?.replace("did:key:", "")}")
                .jwk(subJwk?.toPublicJWK())
                .build()

        val jwt = SignedJWT(
            jwsHeader,
            claimsSet
        )

        // Sign with private EC key
        jwt.sign(
            if (subJwk is OctetKeyPair)
                Ed25519Signer(subJwk)
            else
                ECDSASigner(subJwk as ECKey)
        )
        return jwt.serialize()
    }

    private fun mdocVpToken(
        credentialList: List<String>? = null,
        presentationRequest: PresentationRequest
    ): String {
        // Validate input
        if (credentialList?.isNullOrEmpty() == true) {
            throw IllegalArgumentException("Credential list cannot be empty")
        }
        return try {
            // Extract presentation definition once, as it doesn't change for different credentials
            val presentationDefinition =
                VerificationService().processPresentationDefinition(presentationRequest.presentationDefinition)

            // Create a list to hold documents
            val documentList = mutableListOf<Document>()

            // Iterate over each credential
            for (credential in credentialList ?: emptyList()) {
                // Extract issuer authentication, docType, and namespaces for each credential
                val issuerAuth = CborUtils.processExtractIssuerAuth(listOf(credential))
                val docType = CborUtils.extractDocTypeFromIssuerAuth(listOf(credential))
                val nameSpaces =
                    CborUtils.processExtractNameSpaces(listOf(credential), presentationRequest)


                // Create IssuerSigned object for this credential
                val issuerSigned = IssuerSigned(
                    nameSpaces = nameSpaces,
                    issuerAuth = issuerAuth
                )

                // For each input descriptor, create corresponding documents
                presentationDefinition.inputDescriptors?.forEach { inputDescriptor ->
                    val fieldSize = inputDescriptor.constraints?.fields?.size ?: 0

                    // Create documents based on the number of fields
                    repeat(fieldSize) {
                        documentList.add(
                            Document(
                                docType = docType ?: "",
                                issuerSigned = issuerSigned,
                                deviceSigned = null
                            )
                        )
                    }
                }
            }

            // Create VpToken object
            val generatedVpToken = VpToken(
                version = "1.0",
                documents = documentList,
                status = 0
            )

            // Encode to CBOR
            val encoded = CborUtils.encodeMDocToCbor(generatedVpToken)

            Base64.encodeToString(encoded, Base64.URL_SAFE or Base64.NO_WRAP)

        } catch (e: Exception) {
            Log.e("TAG", "Error generating VP token: ${e.message}")
            throw e // Re-throw or handle it according to your needs
        }
    }

    /**
     * Returns all the list of credentials matching for all input descriptors
     */
    override suspend fun filterCredentials(
        allCredentialList: List<String?>,
        presentationDefinition: PresentationDefinition
    ): List<List<String>> {
        val response: MutableList<MutableList<String>> = mutableListOf()
        val pex = PresentationExchange()

        presentationDefinition.inputDescriptors?.forEach { inputDescriptors ->
            var processedCredentials: MutableList<String> = mutableListOf()
            var credentialList: ArrayList<String?> = arrayListOf()
            var credentialFormat: String? = null
            val formatMap = inputDescriptors.format ?: presentationDefinition.format
            formatMap?.forEach { (key, _) ->
                credentialFormat = key
            }

            if (credentialFormat == "mso_mdoc") {
                credentialList = ArrayList(
                    allCredentialList.filter { credential ->
                        credential != null && !credential.contains(".")
                    }
                )
                processedCredentials.addAll(
                    CborUtils.processMdocCredentialToJsonString(
                        allCredentialList
                    ) ?: emptyList()
                )

            } else {
                credentialList = splitCredentialsBySdJWT(
                    allCredentialList,
                    inputDescriptors.constraints?.limitDisclosure != null
                )
                processedCredentials.addAll(processCredentialsToJsonString(credentialList))
            }

            val filteredCredentialList: MutableList<String> = mutableListOf()
            val updatedInputDescriptor =  updatePath(inputDescriptors)
            val inputDescriptorString = Gson().toJson(updatedInputDescriptor)

            val matches: List<MatchedCredential> =
                pex.matchCredentials(inputDescriptorString, processedCredentials)
            for (match in matches) {
                filteredCredentialList.add(credentialList[match.index] ?: "")
            }

            response.add(filteredCredentialList)
        }

        return response
    }

    private fun updatePath(descriptor: InputDescriptors): InputDescriptors {
        var updatedDescriptor = descriptor.copy()
        val constraints = updatedDescriptor.constraints ?: return updatedDescriptor
        val fields = constraints.fields ?: return updatedDescriptor

        val updatedFields = ArrayList(fields.map { field ->  // Convert to ArrayList
            val pathList = field.path?.toMutableList() ?: mutableListOf()
            val newPathList = ArrayList(pathList) // Ensure ArrayList type

            pathList.forEach { path ->
                if (path.contains("$.vc.")) {
                    val newPath = path.replace("$.vc.", "$.")
                    if (!newPathList.contains(newPath)) {
                        newPathList.add(newPath)
                    }
                }
            }
            field.copy(path = newPathList) // Ensure correct type
        })

        val updatedConstraints = constraints.copy(fields = updatedFields) // Now it's ArrayList<Fields>?
        return updatedDescriptor.copy(constraints = updatedConstraints)
    }

//    fun splitCredentialsBySdJWT(
//        allCredentials: List<String?>,
//        isSdJwt: Boolean
//    ): ArrayList<String?> {
//        val filteredCredentials: ArrayList<String?> = arrayListOf()
//        for (item in allCredentials) {
//            if (isSdJwt && item?.contains("~") == true)
//                filteredCredentials.add(item)
//            else if (!isSdJwt && item?.contains("~") == false)
//                filteredCredentials.add(item)
//        }
//        return filteredCredentials
//    }
fun splitCredentialsBySdJWT(
    allCredentials: List<String?>,
    isSdJwt: Boolean
): ArrayList<String?> {
//        val filteredCredentials: ArrayList<String?> = arrayListOf()
//        for (item in allCredentials) {
//            if (isSdJwt && item?.contains("~") == true)
//                filteredCredentials.add(item)
//            else if (!isSdJwt && item?.contains("~") == false)
//                filteredCredentials.add(item)
//        }
    return ArrayList(allCredentials)
}

    fun processCredentialsToJsonString(credentialList: ArrayList<String?>): List<String> {
        var processedCredentials: List<String> = mutableListOf()
        for (cred in credentialList) {
            val split = cred?.split(".")


            val jsonString = if ((split?.size ?: 0) > 1 && (cred?.split("~")?.size ?: 0) > 0)
            //SDJWTService().updateIssuerJwtWithDisclosuresForFiltering(cred)
                SDJWTService().updateIssuerJwtWithDisclosures(cred)
            else if ((split?.size ?: 0) > 1)
                Base64.decode(
                    split?.get(1) ?: "",
                    Base64.URL_SAFE
                ).toString(charset("UTF-8"))
            else
                "{}"
            val json = JSONObject(jsonString ?: "{}")

            // todo known item, we are considering the path from only vc
            processedCredentials =
                processedCredentials + listOf(
                    if (json.has("vc")) json.getJSONObject("vc").toString()
                    else json.toString()
                )
        }
        return processedCredentials
    }

    /**
     * Processes the provided presentation definition and converts it into a PresentationDefinition object.
     *
     * @param presentationDefinition The presentation definition to be processed, can be of type PresentationDefinition,
     * LinkedTreeMap<*, *> representing JSON structure, or a JSON string.
     * @return The processed PresentationDefinition object.
     * @throws IllegalArgumentException if the presentation definition cannot be processed.
     */
    override fun processPresentationDefinition(presentationDefinition: Any?): PresentationDefinition {
        try {
            return when (presentationDefinition) {
                is PresentationDefinition -> presentationDefinition
                is LinkedTreeMap<*, *> -> {
                    val jsonString = Gson().toJson(presentationDefinition)
                    Gson().fromJson(jsonString, PresentationDefinition::class.java)
                }

                is String -> Gson().fromJson(
                    presentationDefinition,
                    PresentationDefinition::class.java
                )

                else -> {
                    Log.e("VerificationService", "Invalid presentation definition format")
                    PresentationDefinition()
                }
            }
        } catch (e: Exception) {
            Log.e("VerificationService", "Error processing presentation definition", e)
            return PresentationDefinition()
        }
    }

    /**
     * To generate the presentation submission from the presentation Request
     */
    private fun createPresentationSubmission(
        presentationRequest: PresentationRequest
    ): PresentationSubmission {
        val id = UUID.randomUUID().toString()
        val descriptorMap: ArrayList<DescriptorMap> = ArrayList()

        var presentationDefinition: PresentationDefinition? =
            processPresentationDefinition(presentationRequest.presentationDefinition)

        presentationDefinition?.inputDescriptors?.forEachIndexed { index, inputDescriptors ->
            val descriptor = DescriptorMap(
                id = inputDescriptors.id,
                path = "$",
                format =
                presentationDefinition.format?.keys?.firstOrNull()
                    ?: inputDescriptors.format?.keys?.firstOrNull() ?: "jwt_vp",
                pathNested = PathNested(
                    id = inputDescriptors.id,
                    format = "jwt_vc",
                    path = "$.vp.verifiableCredential[$index]"
                )
            )
            descriptorMap.add(descriptor)
        }

        val presentationSubmission = PresentationSubmission(
            id = id,
            definitionId = presentationDefinition?.id,
            descriptorMap = descriptorMap
        )
        return presentationSubmission
    }

    private fun createMdocPresentationSubmission(
        presentationRequest: PresentationRequest
    ): PresentationSubmissionMdoc {
        val id = UUID.randomUUID().toString()
        val descriptorMap: ArrayList<DescriptorMapMdoc> = ArrayList()

        var presentationDefinition: PresentationDefinition? =
            processPresentationDefinition(presentationRequest.presentationDefinition)

        presentationDefinition?.inputDescriptors?.forEachIndexed { index, inputDescriptors ->
            val descriptor = DescriptorMapMdoc(
                id = inputDescriptors.id,
                path = "$",
                format = "mso_mdoc"
            )
            descriptorMap.add(descriptor)
        }

        val presentationSubmission = PresentationSubmissionMdoc(
            id = id,
            definitionId = presentationDefinition?.id,
            descriptorMap = descriptorMap
        )
        return presentationSubmission
    }
}