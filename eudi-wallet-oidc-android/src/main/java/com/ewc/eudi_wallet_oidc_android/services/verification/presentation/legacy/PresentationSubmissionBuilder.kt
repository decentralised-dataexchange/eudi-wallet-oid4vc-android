package com.ewc.eudi_wallet_oidc_android.services.verification.presentation.legacy

import com.ewc.eudi_wallet_oidc_android.models.DescriptorMap
import com.ewc.eudi_wallet_oidc_android.models.PathNested
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.models.PresentationSubmission
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.Presentation
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.PresentationFormat
import com.ewc.eudi_wallet_oidc_android.services.verification.presentationSubMission.PresentationSubmissionGenerator

/**
 * LEGACY, Presentation Exchange: the `presentation_submission` that tells a draft verifier where
 * in the `vp_token` each input descriptor is answered. Paths come from the presentations' final
 * positions, so two mdocs get two descriptors instead of both pointing at the first.
 */
class PresentationSubmissionBuilder {

    fun build(presentations: List<Presentation>, definition: PresentationDefinition): PresentationSubmission {
        val descriptors = ArrayList<DescriptorMap>()
        presentations.forEachIndexed { index, presentation ->
            val path = "$[$index]"
            when (presentation.format) {
                PresentationFormat.MDOC -> presentation.entryIds.forEach { id ->
                    descriptors.add(DescriptorMap(id = id, path = path, format = "mso_mdoc"))
                }
                PresentationFormat.SD_JWT -> presentation.entryIds.forEach { id ->
                    descriptors.add(DescriptorMap(id = id, path = path, format = descriptorFormat(definition, id) ?: "jwt_vp"))
                }
                PresentationFormat.W3C_VP -> presentation.entryIds.forEachIndexed { nested, id ->
                    descriptors.add(
                        DescriptorMap(
                            id = id,
                            path = path,
                            format = w3cFormat(definition, id),
                            pathNested = PathNested(id = id, format = "jwt_vc", path = "$path.vp.verifiableCredential[$nested]"),
                        )
                    )
                }
            }
        }
        return PresentationSubmissionGenerator().generatePresentationSubmission(
            presentations.map { it.token }.toMutableList(), descriptors, definition
        )
    }

    private fun descriptorFormat(definition: PresentationDefinition, id: String): String? =
        definition.inputDescriptors?.firstOrNull { it.id == id }?.format?.keys?.firstOrNull()
            ?: definition.format?.keys?.firstOrNull()

    /** The draft verifiers expect `jwt_vp` or `jwt_vp_json` when they named either; otherwise the descriptor's first format. */
    private fun w3cFormat(definition: PresentationDefinition, id: String): String? {
        val own = definition.inputDescriptors?.firstOrNull { it.id == id }?.format?.keys
        if (!own.isNullOrEmpty()) {
            if ("jwt_vp" in own) return "jwt_vp"
            if ("jwt_vp_json" in own) return "jwt_vp_json"
        }
        val global = definition.format?.keys
        if (!global.isNullOrEmpty()) {
            if ("jwt_vp" in global) return "jwt_vp"
            if ("jwt_vp_json" in global) return "jwt_vp_json"
        }
        return own?.firstOrNull()
    }
}
