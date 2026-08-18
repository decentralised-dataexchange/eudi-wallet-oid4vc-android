package com.ewc.eudi_wallet_oidc_android.services.verification

import android.net.Uri
import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.CredentialList
import com.ewc.eudi_wallet_oidc_android.models.CredentialSet
import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.models.DcqlClaim
import com.ewc.eudi_wallet_oidc_android.models.Meta
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.VPTokenResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.WrappedVpTokenResponse
import com.ewc.eudi_wallet_oidc_android.services.UrlUtils
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletUnitAttestationHeaders
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall.safeApiCallResponse
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.isValidJWT
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest.AuthorisationRequestByJWT
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest.AuthorisationRequestByReferenceWithRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest.AuthorisationRequestByReferenceWithRequestUri
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest.AuthorisationRequestByValue
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest.AuthorisationRequestForIAR
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse.AuthorisationResponseHandler
import com.ewc.eudi_wallet_oidc_android.services.verification.filterCredentials.DCQLCredentialFilter
import com.ewc.eudi_wallet_oidc_android.services.verification.filterCredentials.PresentationDefinitionCredentialFilter
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.nimbusds.jose.jwk.JWK
import org.json.JSONObject

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

        val uri = Uri.parse(data)
        val presentationDefinition = uri.getQueryParameter("presentation_definition")
        val presentationDefinitionUri = uri.getQueryParameter("presentation_definition_uri")
        val dcqlQuery = uri.getQueryParameter("dcql_query")
        val iarOpenid4VPRequest = uri.getQueryParameter("openid4vp_request")

        val requestUri = uri.getQueryParameter("request_uri")
        val request = uri.getQueryParameter("request")
        val wrapped = if (presentationDefinition != null || presentationDefinitionUri != null || dcqlQuery != null) {
            AuthorisationRequestByValue().processAuthorisationRequest(data)
        } else if (!requestUri.isNullOrBlank()) {
            AuthorisationRequestByReferenceWithRequestUri().processAuthorisationRequest(data)
        } else if (request != null) {
            AuthorisationRequestByReferenceWithRequest().processAuthorisationRequest(data)
        } else if (isValidJWT(data)) {
            AuthorisationRequestByJWT().processAuthorisationRequest(data)
        } else if (iarOpenid4VPRequest != null){
            AuthorisationRequestForIAR().processAuthorisationRequest(data)
        } else {
            WrappedPresentationRequest(
                presentationRequest = null,
                errorResponse = ErrorResponse(
                    error = null,
                    errorDescription = "Invalid Request"
                )
            )
        }
        return applySuaEmptyDcqlFallback(wrapped)
    }

    /**
     * Wallet-mediated authorization continuation: after the direct_post, the
     * authorization server 302s to a session-bound web URL. The session lives
     * in the Set-Cookie headers of THAT response, so the URL must be followed
     * here, with those cookies, until a wallet-handleable redirect appears
     * (custom scheme, or a code/error parameter). Returns the final location,
     * or null when the chain does not resolve (caller keeps the original).
     */
    private suspend fun followWalletMediatedContinuation(
        setCookies: List<String>,
        location: String?
    ): String? {
        var url = location ?: return null
        val uri = Uri.parse(url)
        if (uri.scheme != "https" && uri.scheme != "http") return null
        if (uri.getQueryParameter("code") != null || uri.getQueryParameter("error") != null) return null
        val cookies = setCookies.map { it.substringBefore(";") }.toMutableList()
        try {
            repeat(4) {
                val headers = mutableMapOf("Accept" to "application/json")
                if (cookies.isNotEmpty()) headers["Cookie"] = cookies.joinToString("; ")
                val result = safeApiCallResponse {
                    ApiManager.api.getService()?.fetchUrlWithHeaders(url, headers)
                }
                val response = result.getOrNull() ?: return null
                response.headers().values("Set-Cookie").forEach { cookies.add(it.substringBefore(";")) }
                val next = response.headers()["Location"]
                Log.d("VerificationService", "Continuation ${response.code()} $url -> $next")
                when {
                    response.code() in 300..399 && !next.isNullOrEmpty() -> {
                        val nextUri = Uri.parse(next)
                        if (nextUri.scheme != "https" && nextUri.scheme != "http") return next
                        if (nextUri.getQueryParameter("code") != null ||
                            nextUri.getQueryParameter("error") != null
                        ) return next
                        if (next == url) return null
                        url = next
                    }
                    response.isSuccessful -> {
                        val body = response.body()?.string()
                        Log.d("VerificationService", "Continuation body: ${body?.take(500)}")
                        val redirect = try {
                            body?.let { com.google.gson.JsonParser.parseString(it).asJsonObject.get("redirect_uri")?.asString }
                        } catch (e: Exception) { null }
                        return redirect
                    }
                    else -> return null
                }
            }
        } catch (e: Exception) {
            Log.e("VerificationService", "Continuation failed: ${e.message}")
        }
        return null
    }

    /**
     * SUA fallback (e.g. Czech BankID): an authorization request whose DCQL
     * query has NO credential queries asks only for user authentication.
     * The wallet answers it by presenting the PID, so the empty query is
     * replaced with a PID query (SD-JWT or mdoc). Requests with a normal
     * DCQL query or a presentation definition are untouched.
     */
    private fun applySuaEmptyDcqlFallback(wrapped: WrappedPresentationRequest?): WrappedPresentationRequest? {
        val presentationRequest = wrapped?.presentationRequest ?: return wrapped
        val dcql = presentationRequest.dcqlQuery ?: return wrapped
        if (!dcql.credentials.isNullOrEmpty()) return wrapped
        Log.d("VerificationService", "Empty DCQL query (SUA) — falling back to a PID presentation")
        presentationRequest.dcqlQuery = DCQL(
            credentials = listOf(
                // One query, id "pid": with an empty DCQL (SUA), verifiers such
                // as Czech BankID expect the presentation under the DEFAULT
                // query id "pid". No claims list: the PID discloses the claims
                // it holds (a claims list rejects a PID that misses one claim).
                CredentialList(
                    id = "pid",
                    format = "dc+sd-jwt",
                    meta = Meta(
                        vctValues = arrayListOf(
                            "urn:eudi:pid:1",
                            "eu.europa.ec.eudi.pid.1",
                            "urn:eu.europa.ec.eudi:pid:1"
                        )
                    )
                ),
                CredentialList(
                    id = "pid_mdoc",
                    format = "mso_mdoc",
                    meta = Meta(doctypeValue = "eu.europa.ec.eudi.pid.1")
                )
            ),
            credential_sets = listOf(
                CredentialSet(
                    purpose = "User authentication",
                    required = true,
                    options = listOf(listOf("pid"), listOf("pid_mdoc"))
                )
            )
        )
        return wrapped
    }

    override suspend fun processAndSendAuthorisationResponse(
        did: String?,
        subJwk: JWK?,
        presentationRequest: PresentationRequest,
        credentialList: List<String>?,
        walletUnitAttestationJWT: String?,
        walletUnitProofOfPossession: String?,
        isScaFlow: Boolean
    ): WrappedVpTokenResponse {
        val responseUri = presentationRequest.responseUri ?: presentationRequest.redirectUri
        if (responseUri.isNullOrEmpty()) {
            return WrappedVpTokenResponse(
                errorResponse = ErrorResponse(
                    error = null,
                    errorDescription = "Unable to resolve host: $responseUri"
                )
            )
        }

        val headers = WalletUnitAttestationHeaders.build(
            walletUnitAttestationJWT,
            walletUnitProofOfPossession
        )

        return try {
            val params = AuthorisationResponseHandler().prepareAuthorisationResponse(
                presentationRequest = presentationRequest,
                credentialList = credentialList,
                did = did,
                jwk = subJwk,
                isScaFlow = isScaFlow
            )
            Log.d("Params value:", params.toString())

            val result = safeApiCallResponse {
                ApiManager.api.getService()?.sendVPToken(
                    presentationRequest.responseUri ?: presentationRequest.redirectUri ?: "",
                    params,
                    headers
                )
            }

            result.fold(
                onSuccess = { response ->
                    when {
                        response.code() == 200 -> {
                            val bodyString = response.body()?.string()
                            val gson = Gson()
                            try {
                                val vpTokenResponse =
                                    gson.fromJson(bodyString, VPTokenResponse::class.java)
                                WrappedVpTokenResponse(
                                    vpTokenResponse = VPTokenResponse(
                                        redirectUri = vpTokenResponse.redirectUri ?: run {
                                            val jsonObject = gson.fromJson(bodyString, JsonObject::class.java)
                                            jsonObject?.get("code")?.asString?.let { "https://www.example.com?code=$it" }
                                                ?: "https://www.example.com?code=1"
                                        }
                                    )
                                )
                            } catch (e: Exception) {
                                WrappedVpTokenResponse(
                                    vpTokenResponse = VPTokenResponse(
                                        redirectUri = "https://www.example.com?code=1"
                                    )
                                )
                            }
                        }

                        response.code() == 204 -> {
                            val urlValue = response.raw().request.url.toString()
                            if (urlValue.isNullOrEmpty()) {
                                WrappedVpTokenResponse(
                                    errorResponse = ErrorResponse(
                                        error = null,
                                        errorDescription = "The response URL is missing or empty"
                                    )
                                )
                            } else {
                                WrappedVpTokenResponse(
                                    vpTokenResponse = VPTokenResponse(location = urlValue)
                                )
                            }
                        }

                        response.code() == 302 || response.code() == 200 -> {
                            val locationHeader = response.headers()["Location"]
                            if (locationHeader?.contains("error=") == true) {
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
                                // Wallet-mediated authorization (e.g. Czech BankID):
                                // the direct_post answer 302s to a session-bound web
                                // URL that must be followed WITH the response cookies
                                // to complete the authorization and obtain the code.
                                val followed = followWalletMediatedContinuation(
                                    setCookies = response.headers().values("Set-Cookie"),
                                    location = locationHeader
                                )
                                WrappedVpTokenResponse(
                                    vpTokenResponse = VPTokenResponse(
                                        location = followed ?: locationHeader ?: "https://www.example.com?code=1"
                                    )
                                )
                            }
                        }

                        response.code() >= 400 -> {
                            val errorBody = response.errorBody()?.string()
                            val errorMessage =
                                errorBody?.takeIf { it.isNotBlank() } ?: "An unexpected error occurred"
                            WrappedVpTokenResponse(
                                errorResponse = ErrorResponse(
                                    error = response.code(),
                                    errorDescription = errorMessage
                                )
                            )
                        }

                        else -> WrappedVpTokenResponse(
                            errorResponse = ErrorResponse(
                                error = response.code(),
                                errorDescription = "An unexpected error occurred"
                            )
                        )
                    }
                },
                onFailure = { error ->
                    WrappedVpTokenResponse(
                        errorResponse = ErrorResponse(
                            error = null,
                            errorDescription = error.message ?: "Network or API error occurred"
                        )
                    )
                }
            )
        } catch (e: Exception) {
            Log.d("milna", "processAndSendAuthorisationResponse: ${e.message}")
            WrappedVpTokenResponse(
                errorResponse = ErrorResponse(
                    error = null,
                    errorDescription = e.message.toString()
                )
            )
        }
    }

    override suspend fun processAndSendAuthorisationResponseV2(
        did: String?,
        subJwk: JWK?,
        presentationRequest: PresentationRequest,
        credentialList: List<List<String>>?,
        walletUnitAttestationJWT: String?,
        walletUnitProofOfPossession: String?,
        isScaFlow: Boolean,
        jwkList: List<List<JWK?>>?
    ): WrappedVpTokenResponse {
        val responseUri = presentationRequest.responseUri ?: presentationRequest.redirectUri
        if (responseUri.isNullOrEmpty()) {
            return WrappedVpTokenResponse(
                errorResponse = ErrorResponse(
                    error = null,
                    errorDescription = "Unable to resolve host: $responseUri"
                )
            )
        }

        val headers = WalletUnitAttestationHeaders.build(
            walletUnitAttestationJWT,
            walletUnitProofOfPossession
        )

        return try {
            val params = AuthorisationResponseHandler().prepareAuthorisationResponseV2(
                presentationRequest = presentationRequest,
                credentialList = credentialList,
                did = did,
                jwk = subJwk,
                isScaFlow = isScaFlow,
                jwkList = jwkList
            )
            Log.d("Params value:", params.toString())

            val result = safeApiCallResponse {
                ApiManager.api.getService()?.sendVPToken(
                    presentationRequest.responseUri ?: presentationRequest.redirectUri ?: "",
                    params,
                    headers
                )
            }

            result.fold(
                onSuccess = { response ->
                    when {
                        response.code() == 200 -> {
                            val bodyString = response.body()?.string()
                            val gson = Gson()
                            try {
                                val vpTokenResponse =
                                    gson.fromJson(bodyString, VPTokenResponse::class.java)
                                WrappedVpTokenResponse(
                                    vpTokenResponse = VPTokenResponse(
                                        redirectUri = vpTokenResponse.redirectUri ?: run {
                                            val jsonObject = gson.fromJson(bodyString, JsonObject::class.java)
                                            jsonObject?.get("code")?.asString?.let { "https://www.example.com?code=$it" }
                                                ?: "https://www.example.com?code=1"
                                        }
                                    )
                                )
                            } catch (e: Exception) {
                                WrappedVpTokenResponse(
                                    vpTokenResponse = VPTokenResponse(
                                        redirectUri = "https://www.example.com?code=1"
                                    )
                                )
                            }
                        }

                        response.code() == 204 -> {
                            val urlValue = response.raw().request.url.toString()
                            if (urlValue.isNullOrEmpty()) {
                                WrappedVpTokenResponse(
                                    errorResponse = ErrorResponse(
                                        error = null,
                                        errorDescription = "The response URL is missing or empty"
                                    )
                                )
                            } else {
                                WrappedVpTokenResponse(
                                    vpTokenResponse = VPTokenResponse(location = urlValue)
                                )
                            }
                        }

                        response.code() == 302 || response.code() == 200 -> {
                            val locationHeader = response.headers()["Location"]
                            if (locationHeader?.contains("error=") == true) {
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
                                // Wallet-mediated authorization (e.g. Czech BankID):
                                // the direct_post answer 302s to a session-bound web
                                // URL that must be followed WITH the response cookies
                                // to complete the authorization and obtain the code.
                                val followed = followWalletMediatedContinuation(
                                    setCookies = response.headers().values("Set-Cookie"),
                                    location = locationHeader
                                )
                                WrappedVpTokenResponse(
                                    vpTokenResponse = VPTokenResponse(
                                        location = followed ?: locationHeader ?: "https://www.example.com?code=1"
                                    )
                                )
                            }
                        }

                        response.code() >= 400 -> {
                            val errorBody = response.errorBody()?.string()
                            val errorMessage =
                                errorBody?.takeIf { it.isNotBlank() } ?: "An unexpected error occurred"
                            WrappedVpTokenResponse(
                                errorResponse = ErrorResponse(
                                    error = response.code(),
                                    errorDescription = errorMessage
                                )
                            )
                        }

                        else -> WrappedVpTokenResponse(
                            errorResponse = ErrorResponse(
                                error = response.code(),
                                errorDescription = "An unexpected error occurred"
                            )
                        )
                    }
                },
                onFailure = { error ->
                    WrappedVpTokenResponse(
                        errorResponse = ErrorResponse(
                            error = null,
                            errorDescription = error.message ?: "Network or API error occurred"
                        )
                    )
                }
            )
        } catch (e: Exception) {
            Log.d("milna", "processAndSendAuthorisationResponseV2: ${e.message}")
            WrappedVpTokenResponse(
                errorResponse = ErrorResponse(
                    error = null,
                    errorDescription = e.message.toString()
                )
            )
        }
    }

    /**
     * Returns all the list of credentials matching for all input descriptors
     */
    override suspend fun filterCredentials(
        allCredentialList: List<String?>,
        queryItem: Any?
    ): List<List<String>> {
        when (queryItem) {
            is DCQL -> {
                return DCQLCredentialFilter().filterCredentialsUsingDCQL(
                    allCredentialList,
                    queryItem
                )
            }

            is PresentationDefinition -> {
                return PresentationDefinitionCredentialFilter().filterCredentialsUsingPresentationDefinition(
                    allCredentialList,
                    queryItem
                )
            }

            else -> {
                Log.e(
                    "VerificationService",
                    "Invalid query item type: ${queryItem?.javaClass?.name}"
                )
                return emptyList()
            }
        }
    }
}