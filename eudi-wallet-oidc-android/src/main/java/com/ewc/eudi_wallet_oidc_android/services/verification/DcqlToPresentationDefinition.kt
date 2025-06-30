package com.ewc.eudi_wallet_oidc_android.services.verification

import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.models.Fields
import com.ewc.eudi_wallet_oidc_android.models.Filter
import com.ewc.eudi_wallet_oidc_android.models.InputDescriptors
import com.ewc.eudi_wallet_oidc_android.models.Jwt
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import java.util.UUID

class DcqlToPresentationDefinition {
    fun convertToOID4VP(dcql: DCQL?): PresentationDefinition {
        val presentationDefinitionId = UUID.randomUUID().toString()

        val inputDescriptors = dcql?.credentials?.map { credential ->
            val descriptorId = credential.id ?: UUID.randomUUID().toString()

            val claimFields = credential.claims?.mapNotNull { claim ->
                val path = when {
                    // Handle mdoc: use namespace + claim_name
                    claim.namespace != null && claim.claimName != null ->
                        "$['${claim.namespace}']['${claim.claimName}']"

                    // Handle sd-jwt: use dot path notation
                    claim.path != null && claim.path.isNotEmpty() ->
                        "$.${claim.path.last()}"

                    else -> null
                }

                path?.let { Fields(path = arrayListOf(it)) }
            } ?: emptyList()

            val metaFields = when {
                credential.meta?.vctValues?.isNotEmpty() == true -> {
                    val vctValue = credential.meta?.vctValues?.first()
                    listOf(
                        Fields(
                            path = arrayListOf("$.vct", "$.vc.vct"),
                            filter = Filter(
                                type = "string",
                                const = vctValue
                            )
                        )
                    )
                }
                else -> emptyList()
            }

            val allFields = ArrayList<Fields>().apply {
                addAll(claimFields)
                addAll(metaFields)
            }

            val formatMap = credential.format?.let { fmt ->
                mapOf(
                    fmt to Jwt(
                        alg = arrayListOf("ES256", "ES384")
                    )
                )
            }

            InputDescriptors(
                id = descriptorId,
                format = formatMap,
                constraints = com.ewc.eudi_wallet_oidc_android.models.Constraints(
                    fields = allFields,
                    limitDisclosure = "required"
                )
            )
        } ?: emptyList()

        return PresentationDefinition(
            id = presentationDefinitionId,
            inputDescriptors = ArrayList(inputDescriptors)
        )
    }
}