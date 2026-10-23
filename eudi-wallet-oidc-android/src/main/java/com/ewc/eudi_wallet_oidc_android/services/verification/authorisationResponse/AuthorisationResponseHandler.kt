package com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.AuthenticationMethods
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.PresentationException
import com.ewc.eudi_wallet_oidc_android.services.verification.response.LegacySelection
import com.ewc.eudi_wallet_oidc_android.services.verification.response.PresentationSubmitter
import com.ewc.eudi_wallet_oidc_android.services.verification.response.ResponseMode
import com.ewc.eudi_wallet_oidc_android.services.verification.response.SubmissionException
import com.ewc.eudi_wallet_oidc_android.services.verification.transaction.StrongCustomerAuthentication
import com.ewc.eudi_wallet_oidc_android.services.verification.transaction.TransactionData
import com.nimbusds.jose.jwk.JWK

/**
 * Previous API: the encoded response parameters for the request's response mode, without
 * sending them. Hosts that deliver the response themselves, such as the Digital Credentials API
 * path, call this directly. An empty map means there is nothing to send: the mode is not
 * supported, the credentials do not map onto the query, or a proof could not be made.
 */
class AuthorisationResponseHandler {

    @Deprecated("Use VerificationService.submitPresentation")
    suspend fun prepareAuthorisationResponse(
        presentationRequest: PresentationRequest,
        credentialList: List<String>?,
        did: String?,
        jwk: JWK?,
        isScaFlow: Boolean = false
    ): Map<String, String> = prepareAuthorisationResponseV2(
        presentationRequest = presentationRequest,
        credentialList = credentialList?.map { listOf(it) },
        did = did,
        jwk = jwk,
        isScaFlow = isScaFlow,
        amrInherenceFactor = if (isScaFlow) "fingerprint_device" else null,
    )

    suspend fun prepareAuthorisationResponseV2(
        presentationRequest: PresentationRequest,
        credentialList: List<List<String>>?,
        did: String?,
        jwk: JWK?,
        isScaFlow: Boolean = false,
        jwkList: List<List<JWK?>>? = null,
        amrInherenceFactor: String? = null,
        amrKnowledgeFactor: String? = null
    ): Map<String, String> {
        val mode = ResponseMode.of(presentationRequest)
        if (mode is ResponseMode.Unsupported) {
            Logger.w(TAG, "Response mode ${mode.raw} is not supported; nothing to send")
            return emptyMap()
        }
        if (mode.deliveredByHost) {
            // Appendix A.4: the audience over the DC API is the origin, prefixed. Callers of this
            // entry point read the request back afterwards, so it is changed in place as before.
            presentationRequest.clientId = "origin:${presentationRequest.clientId}"
        }
        val selected = LegacySelection.from(presentationRequest, credentialList, jwkList, jwk)
            ?: return emptyMap<String, String>().also { Logger.w(TAG, "The selected credentials do not match the query; nothing to send") }
        return try {
            PresentationSubmitter().prepare(
                request = presentationRequest,
                mode = mode,
                selected = selected,
                identity = WalletIdentity(did, jwk),
                authentication = AuthenticationMethods(amrInherenceFactor, amrKnowledgeFactor),
                strongCustomerAuthentication = isScaFlow || StrongCustomerAuthentication.requested(TransactionData.entriesLenient(presentationRequest)),
            )
        } catch (e: PresentationException) {
            Logger.w(TAG, "Nothing to send: ${e.message}")
            emptyMap()
        } catch (e: SubmissionException) {
            Logger.w(TAG, "Nothing to send: ${e.message}")
            emptyMap()
        }
    }

    private companion object {
        const val TAG = "AuthorisationResponseHandler"
    }
}
