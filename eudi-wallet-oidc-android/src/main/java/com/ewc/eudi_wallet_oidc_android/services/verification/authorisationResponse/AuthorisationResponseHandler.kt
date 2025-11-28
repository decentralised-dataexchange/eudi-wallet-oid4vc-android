package com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.ResponseModes
import com.nimbusds.jose.jwk.JWK
import android.util.Log
import com.google.gson.Gson
import org.json.JSONObject

class AuthorisationResponseHandler {
    companion object {
        private const val TAG = "AuthorisationResponseLog"
    }

    suspend fun prepareAuthorisationResponse(
        presentationRequest: PresentationRequest,
        credentialList: List<String>?,
        did: String?,
        jwk: JWK?,
    ): Map<String, String> {
        Log.d(TAG, "Preparing authorisation response...")
        Log.d(TAG, "Response mode: ${presentationRequest.responseMode}")
        Log.d(TAG, "DID: $did")
        Log.d(TAG, "JWK: $jwk")
        Log.d(TAG, "Credential List: $credentialList")

        when (ResponseModes.fromString(presentationRequest.responseMode ?: "direct_post")) {
            ResponseModes.DIRECT_POST -> {
                Log.d(TAG, "Handling DIRECT_POST response mode.")
                val authorisationResponse = AuthorisationResponseBuilder().buildResponse(
                    presentationRequest = presentationRequest,
                    credentialList = credentialList,
                    did = did,
                    jwk = jwk
                ).also {
                    Log.d(TAG, "DIRECT_POST response built: $it")
                }
                val responseMap: Map<String, String> =
                    authorisationResponse.mapValues { (_, value) ->
                        when (value) {
                            is String -> value
                            null -> ""
                            else -> Gson().toJson(value) // Converts List, Map, etc. to proper JSON string
                        }
                    }
                return responseMap
            }

            ResponseModes.DIRECT_POST_JWT -> {
                Log.d(TAG, "Handling DIRECT_POST_JWT response mode.")
                val authorisationResponsePayload = AuthorisationResponseBuilder().buildResponse(
                    presentationRequest = presentationRequest,
                    credentialList = credentialList,
                    did = did,
                    jwk = jwk
                )
                Log.d(TAG, "DIRECT_POST_JWT payload: $authorisationResponsePayload")

                val jwe = JWEEncrypter().encrypt(
                    payload = authorisationResponsePayload,
                    presentationRequest = presentationRequest
                )
                Log.d(TAG, "Encrypted JWE: $jwe")
                return mapOf("response" to jwe)
            }

            ResponseModes.DC_API -> {
                Log.d(TAG, "Handling DC_API response mode. (Empty response)")
                return mapOf()
            }

            ResponseModes.DC_API_JWT -> {
                Log.d(TAG, "Handling DC_API_JWT response mode. (Empty response)")
                return mapOf()
            }

            ResponseModes.IAR_POST -> {
                val authorisationResponse = AuthorisationResponseBuilder().buildResponse(
                    presentationRequest = presentationRequest,
                    credentialList = credentialList,
                    did = did,
                    jwk = jwk
                ).also {
                    Log.d(TAG, "IAR_POST response built: $it")
                }
                // Convert each value in authorisationResponse to string form
                val processedResponseMap: Map<String, String> = authorisationResponse.mapValues { (_, value) ->
                    when (value) {
                        is String -> value
                        null -> ""
                        else -> Gson().toJson(value)
                    }
                }

                // Convert the entire processed map to JSON string
                val openid4vpPresentationJson = Gson().toJson(processedResponseMap)

                // Return map with auth_session + openid4vp_presentation (json string)
                return mapOf(
                    "auth_session" to (presentationRequest.authSession ?: ""),
                    "openid4vp_presentation" to openid4vpPresentationJson
                )
            }


            ResponseModes.IAR_POST_JWT -> {
                val authorisationResponsePayload = AuthorisationResponseBuilder().buildResponse(
                    presentationRequest = presentationRequest,
                    credentialList = credentialList,
                    did = did,
                    jwk = jwk
                )
                Log.d(TAG, "IAR_POST_JWT payload: $authorisationResponsePayload")

                val jwe = JWEEncrypter().encrypt(
                    payload = authorisationResponsePayload,
                    presentationRequest = presentationRequest
                )
                Log.d(TAG, "Encrypted JWE: $jwe")
                val wrappedResponse = JSONObject().apply {
                    put("response", jwe)
                }

                return mapOf(
                    "auth_session" to (presentationRequest.authSession ?: ""),
                    "openid4vp_presentation" to wrappedResponse.toString()
                )
            }

            else -> {
                Log.d(TAG, "Unknown response mode. Returning empty map.")
                return mapOf()
            }
        }
    }

    suspend fun prepareAuthorisationResponseV2(
        presentationRequest: PresentationRequest,
        credentialList: List<List<String>>?,
        did: String?,
        jwk: JWK?,
    ): Map<String, String> {
        Log.d(TAG, "Preparing authorisation response...")
        Log.d(TAG, "Response mode: ${presentationRequest.responseMode}")
        Log.d(TAG, "DID: $did")
        Log.d(TAG, "JWK: $jwk")
        Log.d(TAG, "Credential List: $credentialList")

        when (ResponseModes.fromString(presentationRequest.responseMode ?: "direct_post")) {
            ResponseModes.DIRECT_POST -> {
                Log.d(TAG, "Handling DIRECT_POST response mode.")
                val authorisationResponse = AuthorisationResponseBuilder().buildResponseV2(
                    presentationRequest = presentationRequest,
                    credentialList = credentialList,
                    did = did,
                    jwk = jwk
                ).also {
                    Log.d(TAG, "DIRECT_POST response built: $it")
                }
                val responseMap: Map<String, String> =
                    authorisationResponse.mapValues { (_, value) ->
                        when (value) {
                            is String -> value
                            null -> ""
                            else -> Gson().toJson(value) // Converts List, Map, etc. to proper JSON string
                        }
                    }
                return responseMap
            }

            ResponseModes.DIRECT_POST_JWT -> {
                Log.d(TAG, "Handling DIRECT_POST_JWT response mode.")
                val authorisationResponsePayload = AuthorisationResponseBuilder().buildResponseV2(
                    presentationRequest = presentationRequest,
                    credentialList = credentialList,
                    did = did,
                    jwk = jwk
                )
                Log.d(TAG, "DIRECT_POST_JWT payload: $authorisationResponsePayload")

                val jwe = JWEEncrypter().encrypt(
                    payload = authorisationResponsePayload,
                    presentationRequest = presentationRequest
                )
                Log.d(TAG, "Encrypted JWE: $jwe")
                return mapOf("response" to jwe)
            }

            ResponseModes.DC_API -> {
                Log.d(TAG, "Handling DC_API response mode. (Empty response)")
                return mapOf()
            }

            ResponseModes.DC_API_JWT -> {
                Log.d(TAG, "Handling DC_API_JWT response mode. (Empty response)")
                return mapOf()
            }

            ResponseModes.IAR_POST -> {
                val authorisationResponse = AuthorisationResponseBuilder().buildResponseV2(
                    presentationRequest = presentationRequest,
                    credentialList = credentialList,
                    did = did,
                    jwk = jwk
                ).also {
                    Log.d(TAG, "IAR_POST response built: $it")
                }
                // Convert each value in authorisationResponse to string form
                val processedResponseMap: Map<String, String> = authorisationResponse.mapValues { (_, value) ->
                    when (value) {
                        is String -> value
                        null -> ""
                        else -> Gson().toJson(value)
                    }
                }

                // Convert the entire processed map to JSON string
                val openid4vpPresentationJson = Gson().toJson(processedResponseMap)

                // Return map with auth_session + openid4vp_presentation (json string)
                return mapOf(
                    "auth_session" to (presentationRequest.authSession ?: ""),
                    "openid4vp_presentation" to openid4vpPresentationJson
                )
            }


            ResponseModes.IAR_POST_JWT -> {
                val authorisationResponsePayload = AuthorisationResponseBuilder().buildResponseV2(
                    presentationRequest = presentationRequest,
                    credentialList = credentialList,
                    did = did,
                    jwk = jwk
                )
                Log.d(TAG, "IAR_POST_JWT payload: $authorisationResponsePayload")

                val jwe = JWEEncrypter().encrypt(
                    payload = authorisationResponsePayload,
                    presentationRequest = presentationRequest
                )
                Log.d(TAG, "Encrypted JWE: $jwe")
                val wrappedResponse = JSONObject().apply {
                    put("response", jwe)
                }

                return mapOf(
                    "auth_session" to (presentationRequest.authSession ?: ""),
                    "openid4vp_presentation" to wrappedResponse.toString()
                )
            }

            else -> {
                Log.d(TAG, "Unknown response mode. Returning empty map.")
                return mapOf()
            }
        }
    }
}