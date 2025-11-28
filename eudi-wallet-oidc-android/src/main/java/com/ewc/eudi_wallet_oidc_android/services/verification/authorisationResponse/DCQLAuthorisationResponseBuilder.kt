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

    fun buildResponse(
        credentialsList: List<String>?,
        presentationRequest: PresentationRequest,
        did: String?,
        jwk: JWK?
    ): Map<String, Any?> {
        val params = mutableMapOf<String, Any?>()
        val presentationDefinition =
            processPresentationDefinition(presentationRequest.presentationDefinition)
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
                    inputDescriptors = if (presentationRequest.dcqlQuery != null)
                        presentationRequest.dcqlQuery?.credentials?.getOrNull(index)
                    else
                        presentationDefinition.inputDescriptors?.getOrNull(index)
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

    fun buildResponseV2(
        credentialsList: List<List<String>>?,
        presentationRequest: PresentationRequest,
        did: String?,
        jwk: JWK?
    ): Map<String, Any?> {
        val params = mutableMapOf<String, Any?>()
        val presentationDefinition =
            processPresentationDefinition(presentationRequest.presentationDefinition)
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
                    inputDescriptors = if (presentationRequest.dcqlQuery != null)
                        presentationRequest.dcqlQuery?.credentials?.getOrNull(index)
                    else
                        presentationDefinition.inputDescriptors?.getOrNull(index)
                )
                val gson = Gson()
                val clientMetadataJson = gson.toJsonTree(presentationRequest.clientMetaDetails).asJsonObject
                val version = clientMetadataJson.getAsJsonPrimitive("version")?.asString
                credentialMap[credential.id ?: ""] = if (version == "draft_23") {
                    vpToken?.get(0) ?: ""
                } else {
                    vpToken
                }
            }
        }

        val mainVpToken = generateMainVPToken(credentialMap)
        params["vp_token"] = mainVpToken
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

    private fun generateVpTokensBasedOnCredentialFormat(
        credential: String,
        presentationRequest: PresentationRequest,
        did: String?,
        type: String?,
        jwk: JWK?,
        inputDescriptors: Any?
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
                inputDescriptors = inputDescriptors
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

    private fun generateVpTokensBasedOnCredentialFormat(
        credential: List<String>,
        presentationRequest: PresentationRequest,
        did: String?,
        type: String?,
        jwk: JWK?,
        inputDescriptors: Any?
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
                inputDescriptors = inputDescriptors
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
