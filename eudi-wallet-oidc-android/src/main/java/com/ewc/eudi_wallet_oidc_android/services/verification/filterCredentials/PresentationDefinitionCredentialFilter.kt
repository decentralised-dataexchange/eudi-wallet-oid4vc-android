package com.ewc.eudi_wallet_oidc_android.services.verification.filterCredentials

import com.ewc.eudi_wallet_oidc_android.models.InputDescriptors
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.services.utils.CborUtils
import com.ewc.eudi_wallet_oidc_android.services.utils.CredentialProcessor.processCredentialsToJsonString
import com.ewc.eudi_wallet_oidc_android.services.utils.CredentialProcessor.splitCredentialsBySdJWT
import com.github.decentraliseddataexchange.presentationexchangesdk.PresentationExchange
import com.github.decentraliseddataexchange.presentationexchangesdk.models.MatchedCredential
import com.google.gson.Gson
import kotlin.collections.component1
import kotlin.collections.component2
import kotlin.collections.forEach

class PresentationDefinitionCredentialFilter {

    fun filterCredentialsUsingPresentationDefinition(
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
}