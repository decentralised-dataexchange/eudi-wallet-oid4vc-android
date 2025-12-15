package com.ewc.eudi_wallet_oidc_android.services

import com.ewc.eudi_wallet_oidc_android.models.CredentialList
import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.services.utils.CborUtils
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
        credentialList: List<String>,
        credentialDocType: ArrayList<String?> ?= null
    ): List<MatchedCredential> {
        val filteredList: MutableList<MatchedCredential> = mutableListOf()
        val claims = credentialFilter.claims
         if (claims.isNullOrEmpty()) {
             return when (credentialFilter.format) {

                 "jwt_vc_json" -> {
                     val typeValues: List<List<String>>? = credentialFilter.meta?.typeValues

                     // If no typeValues provided, we cannot decide which JWT to return
                     // → return empty list (do NOT return all credentials)
                     if (typeValues.isNullOrEmpty()) {
                         return emptyList()
                     }

                     credentialList.mapIndexedNotNull { index, credential ->

                         // Extract credential types exactly the same way as your non-empty claim logic
                         val credentialTypes: List<String> = try {
                             val vcType = JsonPath.read<Any>(credential, "$.vc.type")
                             when (vcType) {
                                 is List<*> -> vcType.filterIsInstance<String>()
                                 is String -> listOf(vcType)
                                 else -> emptyList()
                             }
                         } catch (e: Exception) {
                             try {
                                 val type = JsonPath.read<Any>(credential, "$.type")
                                 when (type) {
                                     is List<*> -> type.filterIsInstance<String>()
                                     is String -> listOf(type)
                                     else -> emptyList()
                                 }
                             } catch (e2: Exception) {
                                 emptyList()
                             }
                         }

                         // Match DCQL-type rules exactly like your working path
                         val matched = typeValues.any { requiredTypes ->
                             requiredTypes.all { it in credentialTypes }
                         }

                         if (!matched) return@mapIndexedNotNull null

                         // If type matches → return full JWT credential
                         MatchedCredential(
                             index = index,
                             fields = listOf(
                                 MatchedField(
                                     index = 0,
                                     path = MatchedPath(
                                         index = 0,
                                         path = "$",
                                         value = JsonPath.read<Any>(credential, "$")
                                     )
                                 )
                             )
                         )
                     }
                 }


                 "dc+sd-jwt" -> {
                     credentialList.mapIndexedNotNull { index, cred ->

                         // 1. Must contain `vct`
                         val matchedVct = try {
                             JsonPath.read<String>(cred, "$.vct")
                         } catch (e: Exception) {
                             return@mapIndexedNotNull null // Not an sd-jwt → skip
                         }

                         // 2. Must match vctValues
                         val vctValues = credentialFilter.meta?.vctValues
                         if (vctValues != null && !vctValues.contains(matchedVct)) {
                             return@mapIndexedNotNull null
                         }
                         MatchedCredential(
                             index = index,
                             fields = emptyList()
                         )

                     }
                 }


                 "mso_mdoc" -> {
                     val requiredDocType = credentialFilter.meta?.doctypeValue

                     credentialList.mapIndexedNotNull { index, credential ->

                         // 2️⃣ Enforce docType match
                         if (!requiredDocType.isNullOrBlank() &&
                             credentialDocType?.getOrNull(index) != requiredDocType) {
                             return@mapIndexedNotNull null
                         }

                         // 3️⃣ No claims → no disclosure
                         MatchedCredential(
                             index = index,
                             fields = emptyList()
                         )
                     }
                 }

                 else -> emptyList()
             }
         }
        //need to check if $ is needed at the beginning of the path
        if (credentialFilter.format == "dc+sd-jwt" || credentialFilter.format == "vc+sd-jwt") {
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
                for ((pathIndex, claim) in claims.withIndex()) { // loop B
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
                for ((pathIndex, claim) in claims.withIndex()) {
                    val namespace = claim.namespace
                    val claimName = claim.claimName
                    val paths = claim.path
                    val path = when {
                        !namespace.isNullOrBlank() && !claimName.isNullOrBlank() -> {
                            "$['$namespace']['$claimName']"
                        }
                        !paths.isNullOrEmpty() -> {
                            var claimPath = "$"
                            for (segment in paths) {
                                claimPath += "['$segment']"
                            }
                            claimPath
                        }
                        else -> {
                            // No valid selector, skip this claim
                            continue@credentialLoop
                        }
                    }
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
        }
        else if (credentialFilter.format == "jwt_vc_json") {
            credentialLoop@ for ((credentialIndex, credential) in credentialList.withIndex()) {
                val matchedFields = mutableListOf<MatchedField>()

                // Read type_values as List<List<String>> from meta
                val typeValues: List<List<String>>? = credentialFilter.meta?.typeValues

                try {
                    val credentialTypes: List<String> = try {
                        val vcType = JsonPath.read<Any>(credential, "$.vc.type")
                        when (vcType) {
                            is List<*> -> vcType.filterIsInstance<String>()
                            is String -> listOf(vcType)
                            else -> emptyList()
                        }
                    } catch (e: Exception) {
                        try {
                            val type = JsonPath.read<Any>(credential, "$.type")
                            when (type) {
                                is List<*> -> type.filterIsInstance<String>()
                                is String -> listOf(type)
                                else -> emptyList()
                            }
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

                for ((pathIndex, claim) in claims.withIndex()) {
                    val joinedPath = claim.path?.joinToString(".") ?: ""
                    val directPath = ensureJsonPathPrefix(basePrefix + joinedPath)
                    val nestedSubjectPath = ensureJsonPathPrefix(basePrefix + "credentialSubject." + joinedPath)

                    var matched: Boolean = false
                    var matchedPath: String? = null
                    var matchedValue: Any? = null

                    // Try direct path first
                    try {
                        matchedValue = JsonPath.read<Any>(credential, directPath)
                        matched = true
                        matchedPath = joinedPath
                    } catch (e1: PathNotFoundException) {
                        // Try nested under credentialSubject
                        try {
                            matchedValue = JsonPath.read<Any>(credential, nestedSubjectPath)
                            matched = true
                            matchedPath = "credentialSubject.$joinedPath"
                        } catch (e2: PathNotFoundException) {
                            println("Claim path not found in jwt_vc_json: $directPath or $nestedSubjectPath")
                            continue@credentialLoop
                        }
                    }

                    if (matched && matchedPath != null && matchedValue != null) {
                        matchedFields.add(
                            MatchedField(
                                index = credentialIndex,
                                path = MatchedPath(
                                    index = pathIndex,
                                    path = matchedPath,
                                    value = matchedValue
                                )
                            )
                        )
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