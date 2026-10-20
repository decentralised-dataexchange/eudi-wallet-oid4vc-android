package com.ewc.eudi_wallet_oidc_android.services.verification

import android.net.Uri
import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.VPTokenResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.models.WrappedVpTokenResponse
import com.ewc.eudi_wallet_oidc_android.services.UrlUtils
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletUnitAttestationHeaders
import com.ewc.eudi_wallet_oidc_android.services.network.ApiManager
import com.ewc.eudi_wallet_oidc_android.services.network.SafeApiCall.safeApiCallResponse
import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils.isValidJWT
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestOutcome
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.AuthenticationMethods
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.SelectedCredential
import com.ewc.eudi_wallet_oidc_android.services.verification.response.LegacySelection
import com.ewc.eudi_wallet_oidc_android.services.verification.response.PresentationOutcome
import com.ewc.eudi_wallet_oidc_android.services.verification.response.PresentationSubmitter
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletAttestation
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestResolver
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse.AuthorisationResponseHandler
import com.ewc.eudi_wallet_oidc_android.services.verification.match.CredentialMatches
import com.ewc.eudi_wallet_oidc_android.services.verification.match.PresentationQuery
import com.ewc.eudi_wallet_oidc_android.services.verification.match.PresentationQueryMatcher
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.nimbusds.jose.jwk.JWK
import org.json.JSONObject

class VerificationService : VerificationServiceInterface {

    private companion object {
        const val TAG = "VerificationService"

        /** What the previous API answered when the verifier accepted without a redirect. */
        const val ACCEPTED_PLACEHOLDER = "https://www.example.com?code=1"
    }

    override suspend fun resolveAuthorizationRequest(
        data: String?,
        policy: PresentationRequestPolicy
    ): PresentationRequestOutcome = PresentationRequestResolver(policy).resolve(data)

    /**
     * Kept for integrators on the previous API. Blank input still answers null, because callers
     * test for that; every other outcome is wrapped as before.
     */
    @Deprecated(
        "Use resolveAuthorizationRequest, which returns a typed outcome instead of a nullable wrapper",
        ReplaceWith("resolveAuthorizationRequest(data)")
    )
    override suspend fun processAuthorisationRequest(data: String?): WrappedPresentationRequest? {
        if (data.isNullOrBlank())
            return null

        return when (val outcome = resolveAuthorizationRequest(data)) {
            is PresentationRequestOutcome.Resolved ->
                WrappedPresentationRequest(presentationRequest = outcome.request)
            is PresentationRequestOutcome.Failed ->
                WrappedPresentationRequest(presentationRequest = null, errorResponse = outcome.error)
        }
    }

    override suspend fun submitPresentation(
        request: PresentationRequest,
        selected: List<SelectedCredential>,
        identity: WalletIdentity,
        attestation: WalletAttestation?,
        authentication: AuthenticationMethods?
    ): PresentationOutcome = PresentationSubmitter().submit(request, selected, identity, attestation, authentication)

    /** Previous API, single credential per entry. Adapts onto the V2 shape. */
    @Deprecated("Use submitPresentation", ReplaceWith("submitPresentation(presentationRequest, selected, identity, attestation)"))
    override suspend fun processAndSendAuthorisationResponse(
        did: String?,
        subJwk: JWK?,
        presentationRequest: PresentationRequest,
        credentialList: List<String>?,
        walletUnitAttestationJWT: String?,
        walletUnitProofOfPossession: String?,
        isScaFlow: Boolean
    ): WrappedVpTokenResponse? = processAndSendAuthorisationResponseV2(
        did = did,
        subJwk = subJwk,
        presentationRequest = presentationRequest,
        credentialList = credentialList?.map { listOf(it) },
        walletUnitAttestationJWT = walletUnitAttestationJWT,
        walletUnitProofOfPossession = walletUnitProofOfPossession,
        isScaFlow = isScaFlow,
        jwkList = null,
        // The V1 path always reported fingerprint as the inherence factor of a strong customer authentication.
        amrInherenceFactor = if (isScaFlow) "fingerprint_device" else null,
        amrKnowledgeFactor = null
    )

    /**
     * Previous API. The credentials and keys arrive as lists aligned by position with the query;
     * the outcome is wrapped the way callers of this entry point expect, placeholder redirect
     * included.
     */
    @Deprecated("Use submitPresentation, which takes SelectedCredential values and returns a typed outcome")
    override suspend fun processAndSendAuthorisationResponseV2(
        did: String?,
        subJwk: JWK?,
        presentationRequest: PresentationRequest,
        credentialList: List<List<String>>?,
        walletUnitAttestationJWT: String?,
        walletUnitProofOfPossession: String?,
        isScaFlow: Boolean,
        jwkList: List<List<JWK?>>?,
        amrInherenceFactor: String?,
        amrKnowledgeFactor: String?
    ): WrappedVpTokenResponse {
        val selected = LegacySelection.from(presentationRequest, credentialList, jwkList, subJwk)
            ?: return WrappedVpTokenResponse(
                errorResponse = ErrorResponse(errorDescription = "The selected credentials do not match the query", errorCode = "invalid_request")
            )
        val outcome = PresentationSubmitter().submit(
            request = presentationRequest,
            selected = selected,
            identity = WalletIdentity(did, subJwk),
            attestation = WalletAttestation(walletUnitAttestationJWT, walletUnitProofOfPossession),
            authentication = if (isScaFlow) AuthenticationMethods(amrInherenceFactor, amrKnowledgeFactor) else null,
        )
        return when (outcome) {
            is PresentationOutcome.Accepted -> WrappedVpTokenResponse(
                vpTokenResponse = when {
                    outcome.redirectUri != null -> VPTokenResponse(redirectUri = outcome.redirectUri)
                    outcome.location != null -> VPTokenResponse(location = outcome.location)
                    // Callers of this entry point test the placeholder to mean "accepted, nowhere to go".
                    else -> VPTokenResponse(redirectUri = ACCEPTED_PLACEHOLDER)
                }
            )
            is PresentationOutcome.Delivered -> WrappedVpTokenResponse(vpTokenResponse = VPTokenResponse(redirectUri = ACCEPTED_PLACEHOLDER))
            is PresentationOutcome.Refused -> WrappedVpTokenResponse(errorResponse = outcome.error)
        }
    }

    /**
     * Returns all the list of credentials matching for all input descriptors
     */
    override suspend fun matchCredentials(
        request: PresentationRequest,
        credentials: List<String?>
    ): CredentialMatches = PresentationQueryMatcher().match(request, credentials)

    /** Previous API: the candidates per query entry, in query order, with nothing about satisfiability. */
    @Deprecated(
        "Use matchCredentials, which names each entry and reports whether the request can be satisfied",
        ReplaceWith("matchCredentials(request, allCredentialList)")
    )
    override suspend fun filterCredentials(
        allCredentialList: List<String?>,
        queryItem: Any?
    ): List<List<String>> {
        val query = when (queryItem) {
            is DCQL -> PresentationQuery.Dcql(queryItem)
            is PresentationDefinition -> PresentationQuery.PresentationDefinition(queryItem)
            else -> {
                Log.e(TAG, "Invalid query item type: ${queryItem?.javaClass?.name}")
                return emptyList()
            }
        }
        return PresentationQueryMatcher().match(query, allCredentialList).asLegacyLists()
    }
}