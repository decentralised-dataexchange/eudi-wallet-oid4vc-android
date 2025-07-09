package com.ewc.eudi_wallet_oidc_android.services.verification

import android.net.Uri
import android.util.Base64
import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.InputDescriptors
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.VPTokenResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.WrappedVpTokenResponse
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.sdjwt.SDJWTService
import com.ewc.eudi_wallet_oidc_android.services.utils.CborUtils
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.isValidJWT
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest.AuthorisationRequestByJWT
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest.AuthorisationRequestByReferenceWithRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest.AuthorisationRequestByReferenceWithRequestUri
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationRequest.AuthorisationRequestByValue
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse.AuthorisationResponseHandler
import com.github.decentraliseddataexchange.presentationexchangesdk.PresentationExchange
import com.github.decentraliseddataexchange.presentationexchangesdk.models.MatchedCredential
import com.google.gson.Gson
import com.google.gson.internal.LinkedTreeMap
import com.nimbusds.jose.jwk.JWK
import org.json.JSONObject
import java.net.InetAddress
import java.net.URL

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

        val requestUri = uri.getQueryParameter("request_uri")
        val request = uri.getQueryParameter("request")

        if (presentationDefinition != null || presentationDefinitionUri != null) {
            return AuthorisationRequestByValue().processAuthorisationRequest(data)
        } else if (!requestUri.isNullOrBlank()) {
            return AuthorisationRequestByReferenceWithRequestUri().processAuthorisationRequest(data)
        } else if(request!=null){
            return AuthorisationRequestByReferenceWithRequest().processAuthorisationRequest(data)
        } else if (isValidJWT(data)) {
            return AuthorisationRequestByJWT().processAuthorisationRequest(data)
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
}