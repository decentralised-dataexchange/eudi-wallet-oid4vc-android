package com.ewc.eudi_wallet_oidc_android.services.verification.vpTokenBuilders

import com.ewc.eudi_wallet_oidc_android.models.InputDescriptors
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.nimbusds.jose.jwk.JWK

interface VpTokenBuilder {
    suspend fun build(
        credentialList: List<String>?,
        presentationRequest: PresentationRequest?,
        did: String?,
        jwk: JWK?,
        inputDescriptors: Any? = null,
        isScaFlow: Boolean = false
    ): String?

    suspend fun buildV2(
        credentialList: List<String>?,
        presentationRequest: PresentationRequest?,
        did: String?,
        jwk: JWK?,
        inputDescriptors: Any? = null,
        isScaFlow: Boolean = false
    ): List<String?>
}