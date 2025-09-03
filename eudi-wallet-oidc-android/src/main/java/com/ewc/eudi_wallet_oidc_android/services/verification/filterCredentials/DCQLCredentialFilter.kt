package com.ewc.eudi_wallet_oidc_android.services.verification.filterCredentials

import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.services.DCQLFiltering
import com.ewc.eudi_wallet_oidc_android.services.utils.CborUtils
import com.ewc.eudi_wallet_oidc_android.services.utils.CredentialProcessor.processCredentialsToJsonString
import com.ewc.eudi_wallet_oidc_android.services.utils.CredentialProcessor.splitCredentialsBySdJWT
import com.ewc.eudi_wallet_oidc_android.services.utils.filterByTrustedAuthorities
import com.github.decentraliseddataexchange.presentationexchangesdk.models.MatchedCredential

class DCQLCredentialFilter {
  suspend fun filterCredentialsUsingDCQL(
        allCredentialList: List<String?>,
        dcqlQuery: DCQL?
    ): List<List<String>> {
        val response: MutableList<MutableList<String>> = mutableListOf()

        dcqlQuery?.credentials?.forEach { dcqlCredential ->
            var processedCredentials: MutableList<String> = mutableListOf()
            var credentialList: ArrayList<String?> = arrayListOf()
            var credentialFormat: String? = null
            credentialFormat = dcqlCredential.format


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
                )
                processedCredentials.addAll(processCredentialsToJsonString(credentialList))
            }

            val filteredCredentialList: MutableList<String> = mutableListOf()

            val matches: List<MatchedCredential> =
                DCQLFiltering.filterCredentialUsingSingleDCQLCredentialFilter(dcqlCredential, processedCredentials)

            for (match in matches) {
                filteredCredentialList.add(credentialList[match.index] ?: "")
            }
            val trustedAuthorities  = dcqlCredential.trustedAuthorities
            val finalFilteredList = if (!trustedAuthorities.isNullOrEmpty()) {
                filterByTrustedAuthorities(filteredCredentialList, trustedAuthorities)
            } else {
                filteredCredentialList
            }

            response.add(finalFilteredList.toMutableList())
        }

        return response
    }
}