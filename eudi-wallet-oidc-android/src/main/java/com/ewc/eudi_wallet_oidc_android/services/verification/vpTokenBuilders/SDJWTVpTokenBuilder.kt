package com.ewc.eudi_wallet_oidc_android.services.verification.vpTokenBuilders

import com.ewc.eudi_wallet_oidc_android.models.CredentialList
import com.ewc.eudi_wallet_oidc_android.models.InputDescriptors
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.AuthenticationMethods
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.PresentationException
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.PresentationInputs
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.SdJwtVpTokenBuilder
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.SelectedCredential
import com.nimbusds.jose.jwk.JWK

/**
 * Previous API. Delegates to [SdJwtVpTokenBuilder] and keeps the old tolerance: a credential
 * whose key binding cannot be signed is returned as it is.
 */
@Deprecated("Use presentation.SdJwtVpTokenBuilder through PresentationBuilder")
class SDJWTVpTokenBuilder : VpTokenBuilder {

    override suspend fun build(
        credentialList: List<String>?,
        presentationRequest: PresentationRequest?,
        did: String?,
        jwk: JWK?,
        inputDescriptors: Any?,
        isScaFlow: Boolean
    ): String? {
        val credential = credentialList?.getOrNull(0) ?: return null
        // The V1 path always reported fingerprint as the inherence factor.
        return present(credential, presentationRequest, did, jwk, inputDescriptors, isScaFlow, AuthenticationMethods(inherence = "fingerprint_device"))
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
        val sca = isScaFlow || LegacyTransactionData.isStrongCustomerAuthentication(presentationRequest)
        return credentialList.mapIndexed { index, credential ->
            present(credential, presentationRequest, did, jwkList?.getOrNull(index) ?: jwk, inputDescriptors, sca, AuthenticationMethods(amrInherenceFactor, amrKnowledgeFactor))
        }
    }

    private fun present(
        credential: String,
        request: PresentationRequest?,
        did: String?,
        key: JWK?,
        entry: Any?,
        sca: Boolean,
        authentication: AuthenticationMethods,
    ): String {
        val entryId = (entry as? InputDescriptors)?.id ?: (entry as? CredentialList)?.id ?: ""
        val inputs = PresentationInputs(
            request = request ?: PresentationRequest(),
            holder = WalletIdentity(did, key),
            transactionDataHashes = mapOf(entryId to LegacyTransactionData.hashesFor(entry, request)),
            strongCustomerAuthentication = sca,
            authentication = authentication,
        )
        return try {
            SdJwtVpTokenBuilder().present(SelectedCredential(entryId, credential, key), inputs).token
        } catch (e: PresentationException) {
            credential
        }
    }
}
