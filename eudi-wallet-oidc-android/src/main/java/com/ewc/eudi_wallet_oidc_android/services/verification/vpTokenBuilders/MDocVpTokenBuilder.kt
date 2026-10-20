package com.ewc.eudi_wallet_oidc_android.services.verification.vpTokenBuilders

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.MdocVpTokenBuilder
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.PresentationBuilder
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.PresentationException
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.PresentationInputs
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.SelectedCredential
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.SessionTranscript
import com.nimbusds.jose.jwk.JWK

/**
 * Previous API. Delegates to [MdocVpTokenBuilder]: one DeviceResponse with every document (V1),
 * or one per credential (V2), where a credential without a usable key is returned as it is.
 */
@Deprecated("Use presentation.MdocVpTokenBuilder through PresentationBuilder")
class MDocVpTokenBuilder : VpTokenBuilder {

    override suspend fun build(
        credentialList: List<String>?,
        presentationRequest: PresentationRequest?,
        did: String?,
        jwk: JWK?,
        inputDescriptors: Any?,
        isScaFlow: Boolean
    ): String? {
        val request = presentationRequest ?: return null
        val credentials = credentialList?.takeIf { it.isNotEmpty() } ?: return null
        val inputs = inputs(request, did, jwk)
        val transcript = SessionTranscript.forRequest(request, inputs.encryptionKeyThumbprint)
        return MdocVpTokenBuilder().presentAll(credentials.map { SelectedCredential("", it, jwk) }, inputs, transcript).token
    }

    override suspend fun buildV2(
        credentialList: List<String>?,
        presentationRequest: PresentationRequest?,
        did: String?,
        jwk: JWK?,
        inputDescriptors: Any?,
        isScaFlow: Boolean,
        jwkList: List<JWK?>?,
        amrInherenceFactor: String?,
        amrKnowledgeFactor: String?
    ): List<String?> {
        val request = presentationRequest ?: return emptyList()
        if (credentialList.isNullOrEmpty()) return emptyList()
        val inputs = inputs(request, did, jwk)
        val transcript = SessionTranscript.forRequest(request, inputs.encryptionKeyThumbprint)
        return credentialList.mapIndexed { index, credential ->
            try {
                MdocVpTokenBuilder().present(SelectedCredential("", credential, jwkList?.getOrNull(index) ?: jwk), inputs, transcript).token
            } catch (e: PresentationException) {
                credential
            }
        }
    }

    private suspend fun inputs(request: PresentationRequest, did: String?, jwk: JWK?) = PresentationInputs(
        request = request,
        holder = WalletIdentity(did, jwk),
        encryptionKeyThumbprint = PresentationBuilder.encryptionKeyThumbprint(request),
    )
}
