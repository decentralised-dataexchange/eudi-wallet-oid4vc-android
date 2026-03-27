package com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse

import android.R
import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.ClientMetaDetails
import com.ewc.eudi_wallet_oidc_android.models.InputDescriptors
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.PresentationDefinitionProcessor.processPresentationDefinition
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationService
import com.ewc.eudi_wallet_oidc_android.services.verification.vpTokenBuilders.JWTVpTokenBuilder
import com.ewc.eudi_wallet_oidc_android.services.verification.vpTokenBuilders.MDocVpTokenBuilder
import com.ewc.eudi_wallet_oidc_android.services.verification.vpTokenBuilders.SDJWTVpTokenBuilder
import com.google.gson.Gson
import com.nimbusds.jose.jwk.JWK


import org.json.JSONObject

class DCQLAuthorisationResponseBuilder {

    suspend fun buildResponse(
        credentialsList: List<String>?,
        presentationRequest: PresentationRequest,
        did: String?,
        jwk: JWK?,
        isScaFlow: Boolean = false
    ): Map<String, Any?> {
        val params = mutableMapOf<String, Any?>()
//        val presentationDefinition =
//            processPresentationDefinition(presentationRequest.presentationDefinition)
        val dcqlCredentials = presentationRequest.dcqlQuery?.credentials
        if (dcqlCredentials == null || credentialsList == null || dcqlCredentials.size != credentialsList.size) {
            println("Mismatch or missing data in dcqlQuery or credentialsList")
            return params
        }

        val credentialMap = mutableMapOf<String, Any?>()
        for ((index, credential) in dcqlCredentials.withIndex()) {
            val credentialType = when {
                credential.meta?.doctypeValue !=null -> "mso_mdoc"
                credential.meta?.vctValues?.isNotEmpty() == true -> "sdjwt"
                credential.meta?.typeValues?.isNotEmpty()== true -> "jwt"
                else -> ""
            }

            if (credentialsList[index].isNotEmpty()) {
                val vpToken = generateVpTokensBasedOnCredentialFormat(
                    credential = credentialsList[index],
                    presentationRequest = presentationRequest,
                    did = did,
                    type = credentialType,
                    jwk = jwk,
                    inputDescriptors =
                        presentationRequest.dcqlQuery?.credentials?.getOrNull(index)
                    else
                        presentationDefinition.inputDescriptors?.getOrNull(index),
                    isScaFlow = isScaFlow
                )
                val gson = Gson()
                val clientMetadataJson = gson.toJsonTree(presentationRequest.clientMetaDetails).asJsonObject
                val version = clientMetadataJson.getAsJsonPrimitive("version")?.asString
                credentialMap[credential.id ?: ""] = if (version == "draft_23") {
                    vpToken ?: ""
                } else {
                    listOf(vpToken)
                }
            }
        }

        val mainVpToken = generateMainVPToken(credentialMap)
        params["vp_token"] = mainVpToken
        params["state"] = presentationRequest.state ?: ""

        return params
    }

    suspend fun buildResponseV2(
        credentialsList: List<List<String>>?,
        presentationRequest: PresentationRequest,
        did: String?,
        jwk: JWK?,
        isScaFlow: Boolean = false
    ): Map<String, Any?> {
        val params = mutableMapOf<String, Any?>()
//        val presentationDefinition =
//            processPresentationDefinition(presentationRequest.presentationDefinition)
        val dcqlCredentials = presentationRequest.dcqlQuery?.credentials
        if (dcqlCredentials == null || credentialsList == null || dcqlCredentials.size != credentialsList.size) {
            println("Mismatch or missing data in dcqlQuery or credentialsList")
            return params
        }

        val credentialMap = mutableMapOf<String, Any?>()
        for ((index, credential) in dcqlCredentials.withIndex()) {
            val credentialType = when {
                credential.meta?.doctypeValue !=null -> "mso_mdoc"
                credential.meta?.vctValues?.isNotEmpty() == true -> "sdjwt"
                credential.meta?.typeValues?.isNotEmpty()== true -> "jwt"
                else -> ""
            }

            if (credentialsList[index].isNotEmpty()) {
                val vpToken = generateVpTokensBasedOnCredentialFormat(
                    credential = credentialsList[index],
                    presentationRequest = presentationRequest,
                    did = did,
                    type = credentialType,
                    jwk = jwk,
                    inputDescriptors =
                        presentationRequest.dcqlQuery?.credentials?.getOrNull(index)
                    else
                        presentationDefinition.inputDescriptors?.getOrNull(index),
                    isScaFlow = isScaFlow
                )
                val gson = Gson()
                if (presentationRequest.clientMetaDetails!=null) {
                    val clientMetadataJson =
                        gson.toJsonTree(presentationRequest.clientMetaDetails).asJsonObject
                    val version = clientMetadataJson.getAsJsonPrimitive("version")?.asString
                    credentialMap[credential.id ?: ""] = if (version == "draft_23") {
                        vpToken?.get(0) ?: ""
                    } else {
                        vpToken
                    }
                }else {
                    credentialMap[credential.id ?: ""] =
                        vpToken

                }
            }
        }

        val mainVpToken = generateMainVPToken(credentialMap)
        params["vp_token"] = mainVpToken
//        params["vp_token"] = com.nimbusds.jose.shaded.json.JSONObject(credentialMap)
        params["state"] = presentationRequest.state ?: ""

        return params
    }

    private fun generateMainVPToken(credentialMap: Map<String, Any?>): String {
        return try {
            JSONObject(credentialMap).toString()
        } catch (e: Exception) {
            ""
        }
    }

    private suspend fun generateVpTokensBasedOnCredentialFormat(
        credential: String,
        presentationRequest: PresentationRequest,
        did: String?,
        type: String?,
        jwk: JWK?,
        inputDescriptors: Any?,
        isScaFlow: Boolean = false
    ): String? {
        return if (type == "mso_mdoc") {
            MDocVpTokenBuilder().build(
                credentialList = listOf(credential),
                presentationRequest = presentationRequest,
                did = did,
                jwk = jwk ,
            )
        } else if (type == "sdjwt") {
            SDJWTVpTokenBuilder().build(
                credentialList = listOf(credential),
                presentationRequest = presentationRequest,
                did = did,
                jwk = jwk ,
                inputDescriptors = inputDescriptors,
                isScaFlow = isScaFlow
            )
        }else if(type == "jwt"){
            JWTVpTokenBuilder().build(
                credentialList = listOf(credential),
                presentationRequest = presentationRequest,
                did = did,
                jwk = jwk
            )
        }
        else{
            null
        }
    }

    private suspend fun generateVpTokensBasedOnCredentialFormat(
        credential: List<String>,
        presentationRequest: PresentationRequest,
        did: String?,
        type: String?,
        jwk: JWK?,
        inputDescriptors: Any?,
        isScaFlow: Boolean = false
    ): List<String?>? {
        return if (type == "mso_mdoc") {
            val vpTokenList: MutableList<String?> = mutableListOf()
            for (i in credential) {
                vpTokenList.add(
                    MDocVpTokenBuilder().build(
                        credentialList = listOf(i),
                        presentationRequest = presentationRequest,
                        did = did,
                        jwk = jwk,
                    )
                )
            }
            return vpTokenList
        } else if (type == "sdjwt") {
            SDJWTVpTokenBuilder().buildV2(
                credentialList = credential,
                presentationRequest = presentationRequest,
                did = did,
                jwk = jwk ,
                inputDescriptors = inputDescriptors,
                isScaFlow = isScaFlow
            )
        }else if(type == "jwt"){
            val vpTokenList: MutableList<String?> = mutableListOf()
            for (i in credential){
                vpTokenList.add(JWTVpTokenBuilder().build(
                    credentialList = listOf(i),
                    presentationRequest = presentationRequest,
                    did = did,
                    jwk = jwk
                ))
            }
            return vpTokenList
        }
        else{
            null
        }
    }
}
