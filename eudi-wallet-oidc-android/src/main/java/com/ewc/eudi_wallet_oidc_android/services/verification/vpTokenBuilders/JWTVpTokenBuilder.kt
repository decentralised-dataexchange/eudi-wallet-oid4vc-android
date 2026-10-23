package com.ewc.eudi_wallet_oidc_android.services.verification.vpTokenBuilders

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.JwtVpTokenBuilder
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.PresentationInputs
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.SelectedCredential
import com.nimbusds.jose.jwk.JWK

/** Previous API. Delegates to [JwtVpTokenBuilder]: one aggregated presentation (V1), or one per credential (V2). */
@Deprecated("Use presentation.JwtVpTokenBuilder through PresentationBuilder")
class JWTVpTokenBuilder : VpTokenBuilder {

    override suspend fun build(
        credentialList: List<String>?,
        presentationRequest: PresentationRequest?,
        did: String?,
        jwk: JWK?,
        inputDescriptors: Any?,
        isScaFlow: Boolean
    ): String? {
        val credentials = credentialList?.takeIf { it.isNotEmpty() } ?: return null
        val inputs = PresentationInputs(request = presentationRequest ?: PresentationRequest(), holder = WalletIdentity(did, jwk))
        return JwtVpTokenBuilder().aggregate(credentials.map { SelectedCredential("", it) }, inputs).token
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
        if (credentialList.isNullOrEmpty()) return emptyList()
        val inputs = PresentationInputs(request = presentationRequest ?: PresentationRequest(), holder = WalletIdentity(did, jwk))
        return credentialList.mapIndexed { index, credential ->
            JwtVpTokenBuilder().present(SelectedCredential("", credential, jwkList?.getOrNull(index)), inputs).token
        }
    }
}
