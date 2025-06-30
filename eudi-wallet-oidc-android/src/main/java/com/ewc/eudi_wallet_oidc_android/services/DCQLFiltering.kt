package com.ewc.eudi_wallet_oidc_android.services

import com.ewc.eudi_wallet_oidc_android.models.CredentialList
import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.jayway.jsonpath.JsonPath
import com.jayway.jsonpath.PathNotFoundException

object DCQLFiltering {

    //Here am going to filter for all the credentials, not considering the credential set
    fun filterCredentialsUsingDCQL(
        dcql: DCQL,
        credentials: List<String>
    ): List<List<String>> {
        val filteredList: MutableList<List<String>> = mutableListOf()
        dcql.credentials?.let { credentialsList ->
            for (credentialFilter in credentialsList) {
                val list = filterCredentialUsingSingleDCQLCredentialFilter(
                    credentialFilter,
                    credentials
                )
                filteredList.add(list)
            }
        }

        return filteredList
    }

    private fun filterCredentialUsingSingleDCQLCredentialFilter(
        credentialFilter: CredentialList,
        credentialList: List<String>
    ): List<String> {
        val filteredList: MutableList<String> = mutableListOf()

        //need to check if $ is needed at the beginning of the path
        if (credentialFilter.format == "dc+sd-jwt") {
            credentialLoop@ for (credential in credentialList) { // loop A

                val vctValues = credentialFilter.meta?.vctValues
                try {
                    val matchedVct = JsonPath.read<String>(credential, "$.vct")
                    if (vctValues != null && !vctValues.contains(matchedVct)) {
                        continue@credentialLoop // if vct does not match, skip to next credential
                    }
                } catch (e: PathNotFoundException) {
                    continue@credentialLoop
                }

                for (claim in credentialFilter.claims) { // loop B
                    val paths = claim.path
                    var found = false
                    val joinedPath = paths?.joinToString(separator = ".") ?: ""
                    try {
                        JsonPath.read<Any>(credential, ensureJsonPathPrefix(joinedPath))
                        found = true
                    } catch (e: PathNotFoundException) {
                        println(e.stackTraceToString())
                    }
                    if (!found) continue@credentialLoop // if no path matched, skip to next credential
                }
                // If all claims matched, add credential to filteredList
                filteredList.add(credential)
            }
        } else if (credentialFilter.format == "mso_mdoc") {
            // if the credential is mdoc, check the doc type from credentialFilter.meta.doctype_value
            val docTypeValue = credentialFilter.meta?.doctypeValue
            credentialLoop@ for (credential in credentialList) {
                try {
                    val matchedDocType = JsonPath.read<String>(credential, "$.docType")
                    if (docTypeValue != null && docTypeValue != matchedDocType) {
                        continue@credentialLoop
                    }

                    for (claim in credentialFilter.claims) {
                        val namespace = claim.namespace
                        val claimName = claim.claimName

                        if (namespace.isNullOrBlank() || claimName.isNullOrBlank()) {
                            continue@credentialLoop
                        }

                        val path = "$['$namespace']['$claimName']"
                        try {
                            JsonPath.read<Any>(credential, path)
                        } catch (e: PathNotFoundException) {
                            println("Claim not found: $path")
                            continue@credentialLoop
                        }
                    }

                    filteredList.add(credential)
                } catch (e: PathNotFoundException) {
                    continue@credentialLoop
                }
            }
        }

        return filteredList
    }

    private fun ensureJsonPathPrefix(path: String): String {
        return if (path.startsWith("$.")) path else if (path.isNotEmpty()) "$.$path" else ""
    }
}