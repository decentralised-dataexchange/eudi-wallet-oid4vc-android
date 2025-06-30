package com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse

import android.R
import com.ewc.eudi_wallet_oidc_android.models.InputDescriptors
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationService
import com.ewc.eudi_wallet_oidc_android.services.verification.vpTokenBuilders.MDocVpTokenBuilder
import com.ewc.eudi_wallet_oidc_android.services.verification.vpTokenBuilders.SDJWTVpTokenBuilder
import com.nimbusds.jose.jwk.JWK


import org.json.JSONObject

class DCQLAuthorisationResponseBuilder {

    fun buildResponse(
        credentialsList: List<String>?,
        presentationRequest: PresentationRequest,
        did: String?,
        jwk: JWK?
    ): Map<String, String> {
        val params = mutableMapOf<String, String>()
        val presentationDefinition =
            VerificationService().processPresentationDefinition(presentationRequest.presentationDefinition)
        val dcqlCredentials = presentationRequest.dcqlQuery?.credentials
        if (dcqlCredentials == null || credentialsList == null || dcqlCredentials.size != credentialsList.size) {
            println("Mismatch or missing data in dcqlQuery or credentialsList")
            return params
        }

        val credentialMap = mutableMapOf<String, String>()
        for ((index, credential) in dcqlCredentials.withIndex()) {
            val hasDoctype = when {
                credential.meta?.doctypeValue !=null -> true
                else -> false
            }

            val vpToken = generateVpTokensBasedOnCredentialFormat(
                credential = credentialsList[index],
                presentationRequest = presentationRequest,
                did = did,
                isMdoc = hasDoctype,
                jwk = jwk,
                inputDescriptors = presentationDefinition.inputDescriptors?.getOrNull(index)
            )

            credentialMap[credential.id ?: ""] = vpToken ?: ""
        }

        val mainVpToken = generateMainVPToken(credentialMap)
        params["vp_token"] = mainVpToken
        params["state"] = presentationRequest.state ?: ""

        return params
    }

    private fun generateMainVPToken(credentialMap: Map<String, String>): String {
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
        isMdoc: Boolean,
        jwk: JWK?,
        inputDescriptors: InputDescriptors?
    ): String? {
        return if (isMdoc) {
            MDocVpTokenBuilder().build(
                credentialList = listOf(credential),
                presentationRequest = presentationRequest,
                did = did,
                jwk = jwk ,
            )
        } else {
            SDJWTVpTokenBuilder().build(
                credentialList = listOf(credential),
                presentationRequest = presentationRequest,
                did = did,
                jwk = jwk ,
                inputDescriptors = inputDescriptors
            )
        }
    }
}
