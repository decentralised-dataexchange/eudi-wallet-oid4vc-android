package com.ewc.eudi_wallet_oidc_android.services.verification.presentationSubMission

import com.ewc.eudi_wallet_oidc_android.models.DescriptorMap
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.models.PresentationSubmission


interface PresentationSubmissionGeneratorInterface {
    fun generatePresentationSubmission(
        vpTokenList: MutableList<String>,
        descriptorMap: ArrayList<DescriptorMap>,
        presentationDefinitionProcess: PresentationDefinition?
    ): PresentationSubmission
}
