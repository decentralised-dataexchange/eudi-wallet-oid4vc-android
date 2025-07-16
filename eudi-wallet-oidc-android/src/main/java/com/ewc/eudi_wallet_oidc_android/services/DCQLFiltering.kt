package com.ewc.eudi_wallet_oidc_android.services

import com.ewc.eudi_wallet_oidc_android.models.CredentialList
import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.github.decentraliseddataexchange.presentationexchangesdk.models.MatchedCredential
import com.github.decentraliseddataexchange.presentationexchangesdk.models.MatchedField
import com.github.decentraliseddataexchange.presentationexchangesdk.models.MatchedPath
import com.jayway.jsonpath.JsonPath
import com.jayway.jsonpath.PathNotFoundException

object DCQLFiltering {

    //Here am going to filter for all the credentials, not considering the credential set
    fun filterCredentialsUsingDCQL(
        dcql: DCQL?,
        credentials: List<String>
    ): List<List<MatchedCredential>> {
        val filteredList: MutableList<List<MatchedCredential>> = mutableListOf()
        dcql?.credentials?.let { credentialsList ->
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

     fun filterCredentialUsingSingleDCQLCredentialFilter(
        credentialFilter: CredentialList,
        credentialList: List<String>
    ): List<MatchedCredential> {
        val filteredList: MutableList<MatchedCredential> = mutableListOf()

        //need to check if $ is needed at the beginning of the path
        if (credentialFilter.format == "dc+sd-jwt") {
            credentialLoop@ for ((credentialIndex, credential) in credentialList.withIndex()) { // loop A

                val matchedFields = mutableListOf<MatchedField>()
                val vctValues = credentialFilter.meta?.vctValues
                try {
                    val matchedVct = JsonPath.read<String>(credential, "$.vct")
                    if (vctValues != null && !vctValues.contains(matchedVct)) {
                        continue@credentialLoop // if vct does not match, skip to next credential
                    }
                } catch (e: PathNotFoundException) {
                    continue@credentialLoop
                }
                for ((pathIndex, claim) in credentialFilter.claims.withIndex()) { // loop B
                    val paths = claim.path
                    val joinedPath = paths?.joinToString(separator = ".") ?: ""
                    try {
                        val matchedPathValue = JsonPath.read<Any>(credential, ensureJsonPathPrefix(joinedPath))

                        matchedFields.add(
                            MatchedField(
                                index = credentialIndex,
                                path = MatchedPath(
                                    index = pathIndex,
                                    path = joinedPath,
                                    value = matchedPathValue
                                )
                            )
                        )
                    } catch (e: PathNotFoundException) {
                        println(e.stackTraceToString())
                        continue@credentialLoop
                    }
                }
                // If all claims matched, add credential to filteredList
                filteredList.add(MatchedCredential(
                    index = credentialIndex,
                    fields = matchedFields
                ))
            }
        } else if (credentialFilter.format == "mso_mdoc") {
            credentialLoop@ for ((credentialIndex, credential) in credentialList.withIndex()) {

                val matchedFields = mutableListOf<MatchedField>()
                for ((pathIndex, claim) in credentialFilter.claims.withIndex()) {
                    val namespace = claim.namespace
                    val claimName = claim.claimName

                    if (namespace.isNullOrBlank() || claimName.isNullOrBlank()) {
                        continue@credentialLoop
                    }

                    val path = "$['$namespace']['$claimName']"
                    try {
                        val matchedPathValue = JsonPath.read<Any>(credential, path)

                        matchedFields.add(
                            MatchedField(
                                index = credentialIndex,
                                path = MatchedPath(
                                    index = pathIndex,
                                    path = path,
                                    value = matchedPathValue
                                )
                            )
                        )
                    } catch (e: PathNotFoundException) {
                        println("Claim not found: $path")
                        continue@credentialLoop
                    }
                }

                filteredList.add(MatchedCredential(
                    index = credentialIndex,
                    fields = matchedFields
                ))
            }
        } else if (credentialFilter.format == "jwt_vc_json") {
            credentialLoop@ for ((credentialIndex, credential) in credentialList.withIndex()) {
                val matchedFields = mutableListOf<MatchedField>()

                // Read type_values as List<List<String>> from meta
                val typeValues: List<List<String>>? = credentialFilter.meta?.typeValues

                try {
                    val credentialTypes: List<String> = try {
                        JsonPath.read(credential, "$.vc.type")
                    } catch (e: Exception) {
                        try {
                            JsonPath.read(credential, "$.type")
                        } catch (e2: Exception) {
                            emptyList()
                        }
                    }

                    // Match DCQL type_values (array of arrays)
                    if (typeValues?.isNotEmpty() == true) {
                        val matched = typeValues.any { requiredTypes ->
                            requiredTypes.all { it in credentialTypes }
                        }
                        if (!matched) {
                            continue@credentialLoop
                        }
                    }
                } catch (e: Exception) {
                    println("Failed to read type from credential: ${e.message}")
                    continue@credentialLoop
                }

                // Determine if "vc" key exists at root in this credential JSON
                val hasVc: Boolean = try {
                    JsonPath.read<Any>(credential, "$.vc")
                    true
                } catch (e: PathNotFoundException) {
                    false
                }

                // Base prefix for claim paths: "vc." if present else ""
                val basePrefix = if (hasVc) "vc." else ""

                // Claim filtering: each claim path under basePrefix
                for ((pathIndex, claim) in credentialFilter.claims.withIndex()) {
                    val joinedPath = claim.path?.joinToString(".") ?: ""
                    val fullPath = ensureJsonPathPrefix(basePrefix + joinedPath)

                    try {
                        val matchedPathValue = JsonPath.read<Any>(credential, fullPath)
                        matchedFields.add(
                            MatchedField(
                                index = credentialIndex,
                                path = MatchedPath(
                                    index = pathIndex,
                                    path = joinedPath,
                                    value = matchedPathValue
                                )
                            )
                        )
                    } catch (e: PathNotFoundException) {
                        println("Claim path not found in jwt_vc_json: $fullPath")
                        continue@credentialLoop
                    }
                }

                // All claims matched, add to results
                filteredList.add(
                    MatchedCredential(
                        index = credentialIndex,
                        fields = matchedFields
                    )
                )
            }
        }

        return filteredList
    }

    private fun ensureJsonPathPrefix(path: String): String {
        return if (path.startsWith("$.")) path else if (path.isNotEmpty()) "$.$path" else ""
    }
}