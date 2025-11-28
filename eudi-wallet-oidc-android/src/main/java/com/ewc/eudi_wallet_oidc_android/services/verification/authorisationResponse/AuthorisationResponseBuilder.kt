package com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse

import android.util.Base64
import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.DescriptorMap
import com.ewc.eudi_wallet_oidc_android.models.DescriptorMapSerializer
import com.ewc.eudi_wallet_oidc_android.models.InputDescriptors
import com.ewc.eudi_wallet_oidc_android.models.PathNested
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.PresentationSubmission
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletAttestationUtil
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletAttestationUtil.generateHash
import com.ewc.eudi_wallet_oidc_android.services.verification.PresentationDefinitionProcessor.processPresentationDefinition
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationService
import com.ewc.eudi_wallet_oidc_android.services.verification.idToken.IdTokenGenerator
import com.ewc.eudi_wallet_oidc_android.services.verification.presentationSubMission.PresentationSubmissionGenerator
import com.ewc.eudi_wallet_oidc_android.services.verification.vpTokenBuilders.JWTVpTokenBuilder
import com.ewc.eudi_wallet_oidc_android.services.verification.vpTokenBuilders.MDocVpTokenBuilder
import com.ewc.eudi_wallet_oidc_android.services.verification.vpTokenBuilders.SDJWTVpTokenBuilder
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import kotlin.collections.contains

class AuthorisationResponseBuilder {
    fun buildResponse(
        presentationRequest: PresentationRequest,
        credentialList: List<String>?,
        did: String?,
        jwk: JWK?,
    ): Map<String, Any?> {
        var params = mapOf<String, Any?>()
        if (presentationRequest.dcqlQuery != null) {
            return DCQLAuthorisationResponseBuilder().buildResponse(
                presentationRequest = presentationRequest,
                credentialsList = credentialList,
                did = did,
                jwk = jwk
            )
        } else {
            var vpToken: List<String>? = null
            var idToken: String? = null
            var presentationSubmission: PresentationSubmission? = null

            val processTokenResponse =
                processTokenRequest(presentationRequest, did, credentialList, jwk)
            vpToken = processTokenResponse.first
            Log.d("processAndSendAuthorisationResponse", "vpToken:$vpToken")
            idToken = processTokenResponse.second
            Log.d("processAndSendAuthorisationResponse", "idToken:$idToken")
            presentationSubmission = processTokenResponse.third
            val gson = if (presentationSubmission != null) {
                // Create the custom Gson instance only if presentationSubmission is not null
                GsonBuilder()
                    .registerTypeAdapter(DescriptorMap::class.java, DescriptorMapSerializer())
                    .create()
            } else {
                null
            }
            Log.d(
                "processAndSendAuthorisationResponse",
                "presentationSubmission:${gson?.toJson(presentationSubmission)}"
            )
            when (presentationRequest.responseType) {
                "vp_token" -> {
                    params = mapOf(
                            "vp_token" to (if ((vpToken?.size ?: 0) > 1) {
                                Gson().toJson(vpToken)
                            } else {
                                vpToken?.getOrNull(0)
                                    ?: ""
                            }),
                            "presentation_submission" to presentationSubmission?.let { Gson().fromJson(Gson().toJson(it), HashMap::class.java) },
                            "state" to (presentationRequest.state ?: "")
                        )

                }

                "id_token" -> {
                    params = mapOf(
                        "id_token" to (idToken ?: ""),
                        "state" to (presentationRequest.state ?: "")
                    )
                }

                "vp_token+id_token" -> {
                    params = mapOf(
                            "vp_token" to (if ((vpToken?.size ?: 0) > 1) {
                                Gson().toJson(vpToken)
                            } else {
                                vpToken?.getOrNull(0)
                                    ?: ""
                            }),
                            "id_token" to (idToken ?: ""),
                        "presentation_submission" to presentationSubmission?.let { Gson().fromJson(Gson().toJson(it), HashMap::class.java) },
                            "state" to (presentationRequest.state ?: "")
                        )
                }

                else -> {
                    params = mapOf()
                }
            }
        }
        println("Params sent: $params")
        return params
    }

    fun buildResponseV2(
        presentationRequest: PresentationRequest,
        credentialList: List<List<String>>?,
        did: String?,
        jwk: JWK?,
    ): Map<String, Any?> {
        var params = mapOf<String, Any?>()
        if (presentationRequest.dcqlQuery != null) {
            return DCQLAuthorisationResponseBuilder().buildResponseV2(
                presentationRequest = presentationRequest,
                credentialsList = credentialList,
                did = did,
                jwk = jwk
            )
        } else {
            var vpToken: List<String>? = null
            var idToken: String? = null
            var presentationSubmission: PresentationSubmission? = null

            val processTokenResponse =
                processTokenRequestV2(presentationRequest, did, credentialList, jwk)
            vpToken = processTokenResponse.first
            Log.d("processAndSendAuthorisationResponse", "vpToken:$vpToken")
            idToken = processTokenResponse.second
            Log.d("processAndSendAuthorisationResponse", "idToken:$idToken")
            presentationSubmission = processTokenResponse.third
            val gson = if (presentationSubmission != null) {
                // Create the custom Gson instance only if presentationSubmission is not null
                GsonBuilder()
                    .registerTypeAdapter(DescriptorMap::class.java, DescriptorMapSerializer())
                    .create()
            } else {
                null
            }
            Log.d(
                "processAndSendAuthorisationResponse",
                "presentationSubmission:${gson?.toJson(presentationSubmission)}"
            )
            when (presentationRequest.responseType) {
                "vp_token" -> {
                    params = mapOf(
                        "vp_token" to (if ((vpToken?.size ?: 0) > 1) {
                            Gson().toJson(vpToken)
                        } else {
                            vpToken?.getOrNull(0)
                                ?: ""
                        }),
                        "presentation_submission" to presentationSubmission?.let { Gson().fromJson(Gson().toJson(it), HashMap::class.java) },
                        "state" to (presentationRequest.state ?: "")
                    )

                }

                "id_token" -> {
                    params = mapOf(
                        "id_token" to (idToken ?: ""),
                        "state" to (presentationRequest.state ?: "")
                    )
                }

                "vp_token+id_token" -> {
                    params = mapOf(
                        "vp_token" to (if ((vpToken?.size ?: 0) > 1) {
                            Gson().toJson(vpToken)
                        } else {
                            vpToken?.getOrNull(0)
                                ?: ""
                        }),
                        "id_token" to (idToken ?: ""),
                        "presentation_submission" to presentationSubmission?.let { Gson().fromJson(Gson().toJson(it), HashMap::class.java) },
                        "state" to (presentationRequest.state ?: "")
                    )
                }

                else -> {
                    params = mapOf()
                }
            }
        }
        println("Params sent: $params")
        return params
    }

     fun processTokenRequest(
        presentationRequest: PresentationRequest,
        did: String?,
        credentialList: List<String>?,
        subJwk: JWK?
    ): Triple<List<String>?, String?, PresentationSubmission?> {

        val vpTokenList: MutableList<String> = mutableListOf()
        var idToken: String? = null
        var presentationSubmission: PresentationSubmission? = null

        if (presentationRequest.responseType?.contains("vp_token") == true) {

            val jwtList: MutableList<String> = mutableListOf()
            val mdocList: MutableList<String> = mutableListOf()
            val descriptorMap: ArrayList<DescriptorMap> = ArrayList()

            val presentationDefinitionProcess: PresentationDefinition? =
                processPresentationDefinition(presentationRequest.presentationDefinition)
            credentialList?.let { credentials ->
                val presentationDefinition =
                    processPresentationDefinition(presentationRequest.presentationDefinition)

                credentials.forEachIndexed { credentialIndex, credential ->
                    try {
                        var claimsSet: JWTClaimsSet? = null
                        if (presentationDefinition.inputDescriptors?.getOrNull(credentialIndex)?.format?.containsKey(
                                "mso_mdoc"
                            ) != true &&
                            presentationDefinition.format?.containsKey("mso_mdoc") != true
                        ) {
                            val jwt: JWT = JWTParser.parse(credential)
                            claimsSet = jwt.jwtClaimsSet
                        }

                        // Mdoc

                        if (presentationDefinition.inputDescriptors?.getOrNull(credentialIndex)?.format?.contains(
                                "mso_mdoc"
                            ) == true ||
                            presentationDefinition.format?.contains("mso_mdoc") == true
                        ) {
                                mdocList.add(credential)
                                if (!vpTokenList.contains("mdoc")) {
                                    vpTokenList.add("mdoc")
                                }

                                val currentVpTokenIndex = vpTokenList.indexOf("mdoc")
                                val descriptor = DescriptorMap(
                                    id = presentationDefinition.inputDescriptors?.getOrNull(
                                        credentialIndex
                                    )?.id,
                                    path = "$[$currentVpTokenIndex]", // vpTokenList index
                                    format = "mso_mdoc"
                                )
                                descriptorMap.add(descriptor)


                        }
                        // sdjwt

                        else if (claimsSet?.getStringClaim("vct") != null) {
                            val inputDescriptors = presentationDefinition.inputDescriptors?.getOrNull(credentialIndex)
                            val updatedCredential =   SDJWTVpTokenBuilder().build(
                                credentialList = listOf(credential),
                                presentationRequest = presentationRequest,
                                did = did,
                                jwk = subJwk ,
                                inputDescriptors = inputDescriptors
                            )
                            if (updatedCredential!=null)
                            {
                                vpTokenList.add(updatedCredential)
                                val currentVpTokenIndex = vpTokenList.lastIndex

                                val descriptor = DescriptorMap(
                                    id = presentationDefinition.inputDescriptors?.getOrNull(
                                        credentialIndex
                                    )?.id,
                                    path = "$[$currentVpTokenIndex]", // vpTokenList index
                                    format = presentationDefinition.inputDescriptors?.getOrNull(
                                        credentialIndex
                                    )?.format?.keys?.firstOrNull()
                                        ?: presentationDefinition.format?.keys?.firstOrNull()
                                        ?: "jwt_vp"
                                )
                                descriptorMap.add(descriptor)

                            }
                        }
                        //jwt

                        else {
                            jwtList.add(credential)
                            if (!vpTokenList.contains("jwt")) {
                                vpTokenList.add("jwt")
                            }
                            val currentVpTokenIndex = vpTokenList.indexOf("jwt")
                            val currentJwtListIndex = jwtList.lastIndex

                            val descriptor = DescriptorMap(
                                id = presentationDefinition.inputDescriptors?.getOrNull(
                                    credentialIndex
                                )?.id,
                                path = "$[$currentVpTokenIndex]", // vpTokenList index
                                format = fetchFormat(presentationDefinition,credentialIndex),
                                pathNested = PathNested(
                                    id = presentationDefinition.inputDescriptors?.getOrNull(
                                        credentialIndex
                                    )?.id,
                                    format = "jwt_vc",
                                    path = "$[$currentVpTokenIndex].vp.verifiableCredential[$currentJwtListIndex]" // jwtList index
                                )
                            )
                            descriptorMap.add(descriptor)
                        }
                    } catch (e: Exception) {
                        Log.d("processTokenRequest:", "${e.message}")
                    }
                }
                if (presentationRequest.dcqlQuery == null){
                    presentationSubmission= PresentationSubmissionGenerator().generatePresentationSubmission(vpTokenList,descriptorMap,presentationDefinitionProcess)
                }
            }

            if (jwtList.isNotEmpty()) {
                val jwtSerialize = JWTVpTokenBuilder().build(
                    credentialList = credentialList,
                    presentationRequest = presentationRequest,
                    did = did,
                    jwk = subJwk
                )

                // Replace "jwt" with jwtSerialize in vpTokenList if "jwt" is present
                val jwtIndex = vpTokenList.indexOf("jwt")
                if (jwtIndex != -1) {
                    vpTokenList[jwtIndex] = jwtSerialize ?: ""
                }
            }
            if (mdocList.isNotEmpty()) {
                val cborToken = MDocVpTokenBuilder().build(
                    credentialList = mdocList,
                    presentationRequest = presentationRequest,
                    did = did,
                    jwk = subJwk
                )

                // Replace "mdoc" with cborToken in vpTokenList if "mdoc" is present
                val mdocIndex = vpTokenList.indexOf("mdoc")
                if (mdocIndex != -1) {
                    vpTokenList[mdocIndex] = cborToken ?: ""
                }

            }

        }

        if (presentationRequest.responseType?.contains("id_token") == true) {
            idToken = IdTokenGenerator().generateIdToken(
                presentationRequest,
                did,
                subJwk
            )
        }

        return Triple(vpTokenList, idToken, presentationSubmission)
    }

    fun processTokenRequestV2(
        presentationRequest: PresentationRequest,
        did: String?,
        credentialList: List<List<String>>?,
        subJwk: JWK?
    ): Triple<List<String>?, String?, PresentationSubmission?> {

        val vpTokenList: MutableList<String> = mutableListOf()
        var idToken: String? = null
        var presentationSubmission: PresentationSubmission? = null

        if (presentationRequest.responseType?.contains("vp_token") == true) {

            val jwtList: MutableList<String> = mutableListOf()
            val mdocList: MutableList<String> = mutableListOf()
            val descriptorMap: ArrayList<DescriptorMap> = ArrayList()

            val presentationDefinitionProcess: PresentationDefinition? =
                processPresentationDefinition(presentationRequest.presentationDefinition)
            credentialList?.let { credentials ->
                val presentationDefinition =
                    processPresentationDefinition(presentationRequest.presentationDefinition)

                credentials.forEachIndexed { credentialIndex, credential ->
                    try {
                        var claimsSet: JWTClaimsSet? = null
                        if (presentationDefinition.inputDescriptors?.getOrNull(credentialIndex)?.format?.containsKey(
                                "mso_mdoc"
                            ) != true &&
                            presentationDefinition.format?.containsKey("mso_mdoc") != true
                        ) {
                            val jwt: JWT = JWTParser.parse(credential.getOrNull(0))
                            claimsSet = jwt.jwtClaimsSet
                        }

                        // Mdoc

                        if (presentationDefinition.inputDescriptors?.getOrNull(credentialIndex)?.format?.contains(
                                "mso_mdoc"
                            ) == true ||
                            presentationDefinition.format?.contains("mso_mdoc") == true
                        ) {
                            mdocList.add(credential.getOrNull(0)?:"")
                            if (!vpTokenList.contains("mdoc")) {
                                vpTokenList.add("mdoc")
                            }

                            val currentVpTokenIndex = vpTokenList.indexOf("mdoc")
                            val descriptor = DescriptorMap(
                                id = presentationDefinition.inputDescriptors?.getOrNull(
                                    credentialIndex
                                )?.id,
                                path = "$[$currentVpTokenIndex]", // vpTokenList index
                                format = "mso_mdoc"
                            )
                            descriptorMap.add(descriptor)


                        }
                        // sdjwt

                        else if (claimsSet?.getStringClaim("vct") != null) {
                            val inputDescriptors = presentationDefinition.inputDescriptors?.getOrNull(credentialIndex)
                            val updatedCredential =   SDJWTVpTokenBuilder().build(
                                credentialList = credential,
                                presentationRequest = presentationRequest,
                                did = did,
                                jwk = subJwk ,
                                inputDescriptors = inputDescriptors
                            )
                            if (updatedCredential!=null)
                            {
                                vpTokenList.add(updatedCredential)
                                val currentVpTokenIndex = vpTokenList.lastIndex

                                val descriptor = DescriptorMap(
                                    id = presentationDefinition.inputDescriptors?.getOrNull(
                                        credentialIndex
                                    )?.id,
                                    path = "$[$currentVpTokenIndex]", // vpTokenList index
                                    format = presentationDefinition.inputDescriptors?.getOrNull(
                                        credentialIndex
                                    )?.format?.keys?.firstOrNull()
                                        ?: presentationDefinition.format?.keys?.firstOrNull()
                                        ?: "jwt_vp"
                                )
                                descriptorMap.add(descriptor)

                            }
                        }
                        //jwt

                        else {
                            jwtList.add(credential.getOrNull(0)?:"")
                            if (!vpTokenList.contains("jwt")) {
                                vpTokenList.add("jwt")
                            }
                            val currentVpTokenIndex = vpTokenList.indexOf("jwt")
                            val currentJwtListIndex = jwtList.lastIndex

                            val descriptor = DescriptorMap(
                                id = presentationDefinition.inputDescriptors?.getOrNull(
                                    credentialIndex
                                )?.id,
                                path = "$[$currentVpTokenIndex]", // vpTokenList index
                                format = fetchFormat(presentationDefinition,credentialIndex),
                                pathNested = PathNested(
                                    id = presentationDefinition.inputDescriptors?.getOrNull(
                                        credentialIndex
                                    )?.id,
                                    format = "jwt_vc",
                                    path = "$[$currentVpTokenIndex].vp.verifiableCredential[$currentJwtListIndex]" // jwtList index
                                )
                            )
                            descriptorMap.add(descriptor)
                        }
                    } catch (e: Exception) {
                        Log.d("processTokenRequest:", "${e.message}")
                    }
                }
                if (presentationRequest.dcqlQuery == null){
                    presentationSubmission= PresentationSubmissionGenerator().generatePresentationSubmission(vpTokenList,descriptorMap,presentationDefinitionProcess)
                }
            }

            if (jwtList.isNotEmpty()) {
                val jwtSerialize = JWTVpTokenBuilder().build(
                    credentialList = jwtList,
                    presentationRequest = presentationRequest,
                    did = did,
                    jwk = subJwk
                )

                // Replace "jwt" with jwtSerialize in vpTokenList if "jwt" is present
                val jwtIndex = vpTokenList.indexOf("jwt")
                if (jwtIndex != -1) {
                    vpTokenList[jwtIndex] = jwtSerialize ?: ""
                }
            }
            if (mdocList.isNotEmpty()) {
                val cborToken = MDocVpTokenBuilder().build(
                    credentialList = mdocList,
                    presentationRequest = presentationRequest,
                    did = did,
                    jwk = subJwk
                )

                // Replace "mdoc" with cborToken in vpTokenList if "mdoc" is present
                val mdocIndex = vpTokenList.indexOf("mdoc")
                if (mdocIndex != -1) {
                    vpTokenList[mdocIndex] = cborToken ?: ""
                }

            }

        }

        if (presentationRequest.responseType?.contains("id_token") == true) {
            idToken = IdTokenGenerator().generateIdToken(
                presentationRequest,
                did,
                subJwk
            )
        }

        return Triple(vpTokenList, idToken, presentationSubmission)
    }

    private fun checkTransactionDataWithInputDescriptor(
        inputDescriptors: InputDescriptors?,
        transactionDataItem: String?
    ): Boolean {
        return try {
            val decodedData = String(Base64.decode(transactionDataItem, Base64.URL_SAFE), StandardCharsets.UTF_8)
            val jsonObject = JSONObject(decodedData)
            val credentialIds = jsonObject.optJSONArray("credential_ids")?.let { array ->
                List(array.length()) { array.getString(it) }
            } ?: emptyList()

            inputDescriptors?.id in credentialIds
        } catch (e: Exception) {
            Log.e("VerificationService", "Error processing transaction data: ${e.message}")
            false
        }
    }

    private fun fetchFormat(presentationDefinition: PresentationDefinition, credentialIndex: Int): String? {
        val inputDescriptorKeys = presentationDefinition.inputDescriptors
            ?.getOrNull(credentialIndex)
            ?.format
            ?.keys

        if (!inputDescriptorKeys.isNullOrEmpty()) {
            if ("jwt_vp" in inputDescriptorKeys) return "jwt_vp"
            if ("jwt_vp_json" in inputDescriptorKeys) return "jwt_vp_json"
        }

        val globalFormatKeys = presentationDefinition.format?.keys

        if (!globalFormatKeys.isNullOrEmpty()) {
            if ("jwt_vp" in globalFormatKeys) return "jwt_vp"
            if ("jwt_vp_json" in globalFormatKeys) return "jwt_vp_json"
        }

        return inputDescriptorKeys?.firstOrNull()
    }
}
