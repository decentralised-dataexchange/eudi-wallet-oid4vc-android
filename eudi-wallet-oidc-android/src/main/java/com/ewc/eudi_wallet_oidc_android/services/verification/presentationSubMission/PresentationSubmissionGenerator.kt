package com.ewc.eudi_wallet_oidc_android.services.verification.presentationSubMission

import com.ewc.eudi_wallet_oidc_android.models.DescriptorMap
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.models.PresentationSubmission
import java.util.UUID

class PresentationSubmissionGenerator : PresentationSubmissionGeneratorInterface {
    override fun generatePresentationSubmission(
        vpTokenList: MutableList<String>,
        descriptorMap: ArrayList<DescriptorMap>,
        presentationDefinitionProcess: PresentationDefinition?
    ): PresentationSubmission {
        if (vpTokenList.size == 1) {
            // If the list size is 1, replace "$[anyindex]" with "$" in descriptorMap
            descriptorMap.forEach { descriptor ->
                descriptor.path =
                    descriptor.path?.replaceFirst(Regex("\\$\\[.*?\\]"), "\\$")

                // If pathNested exists and its path is not null, update its path
                descriptor.pathNested?.let { pathNested ->
                    pathNested.path?.let {
                        pathNested.path =
                            it.replaceFirst(Regex("\\$\\[.*?\\](?=\\.)"), "\\$")
                    }
                }
            }
        }

        val id = UUID.randomUUID().toString()
        val presentationSubmission = PresentationSubmission(
            id = id,
            definitionId = presentationDefinitionProcess?.id,
            descriptorMap = descriptorMap
        )
        return presentationSubmission
    }
}