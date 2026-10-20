package com.ewc.eudi_wallet_oidc_android.services.verification

import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.PresentationSubmission
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.WrappedVpTokenResponse
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestOutcome
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy
import com.github.decentraliseddataexchange.presentationexchangesdk.PresentationExchange
import com.github.decentraliseddataexchange.presentationexchangesdk.models.MatchedCredential
import com.google.gson.Gson
import com.google.gson.internal.LinkedTreeMap
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK

interface VerificationServiceInterface {

    /**
     * Resolves scanned data (QR code or deep link) into a presentation request.
     *
     * OpenID4VP 1.0 lets a verifier pass the request by value in the URI, as a `request` object,
     * or behind a `request_uri` fetched by GET or by POST (section 5.10). Draft parameters such as
     * `presentation_definition` are accepted while [policy] allows them.
     *
     * @param data the full data scanned from the QR code or received in the deep link
     * @param policy what to accept; [PresentationRequestPolicy.Default] is the SDK's existing behaviour
     */
    suspend fun resolveAuthorizationRequest(
        data: String?,
        policy: PresentationRequestPolicy = PresentationRequestPolicy.Default
    ): PresentationRequestOutcome

    /**
     * Previous API. Returns null for blank input, otherwise the outcome of
     * [resolveAuthorizationRequest] wrapped as a [WrappedPresentationRequest].
     */
    @Deprecated(
        "Use resolveAuthorizationRequest, which returns a typed outcome instead of a nullable wrapper",
        ReplaceWith("resolveAuthorizationRequest(data)")
    )
    suspend fun processAuthorisationRequest(data: String?): WrappedPresentationRequest?

    suspend fun processAndSendAuthorisationResponse(
        did: String?,
        subJwk: JWK?,
        presentationRequest: PresentationRequest,
        credentialList: List<String>? = null,
        walletUnitAttestationJWT: String? ,
        walletUnitProofOfPossession: String?,
        isScaFlow: Boolean = false
    ): WrappedVpTokenResponse?

    suspend fun processAndSendAuthorisationResponseV2(
        did: String?,
        subJwk: JWK?,
        presentationRequest: PresentationRequest,
        credentialList: List<List<String>>? = null,
        walletUnitAttestationJWT: String? ,
        walletUnitProofOfPossession: String?,
        isScaFlow: Boolean = false,
        jwkList: List<List<JWK?>>? = null,
        amrInherenceFactor: String? = null,
        amrKnowledgeFactor: String? = null
    ): WrappedVpTokenResponse?

    /**
     * To filter the credential using the input descriptors
     * @param credentialList - list of all issued credentials
     * @param presentationDefinition
     *
     * @return list of credentials filtered using the presentation definition
     */
    suspend fun filterCredentials(
        credentialList: List<String?>,
        queryItem: Any?
    ): List<List<String>>
}