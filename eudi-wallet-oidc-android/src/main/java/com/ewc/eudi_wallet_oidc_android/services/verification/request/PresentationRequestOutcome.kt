package com.ewc.eudi_wallet_oidc_android.services.verification.request

import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.client.VerifierIdentity

/**
 * What resolving scanned data into a presentation request produced.
 *
 * Replaces a nullable `WrappedPresentationRequest` whose two nullable fields left callers to work
 * out which of "nothing scanned", "request refused" and "request ready" they were looking at.
 */
sealed class PresentationRequestOutcome {

    /**
     * The request is ready for credential matching.
     *
     * @param request the parsed request, with any `presentation_definition_uri` and
     *   `client_metadata_uri` already dereferenced.
     * @param specVersion which revision of OpenID4VP the request follows.
     * @param source the registry name of the transfer mechanism that carried it, for logs.
     * @param verifier what the client identifier check established about the verifier: which
     *   prefix, whether the request is authenticated, whether the key is anchored.
     */
    data class Resolved(
        val request: PresentationRequest,
        val specVersion: PresentationRequestSpecVersion,
        val source: String,
        val verifier: VerifierIdentity,
    ) : PresentationRequestOutcome()

    /** The data was not a presentation request, or was one the policy or the spec refuses. */
    data class Failed(val error: ErrorResponse) : PresentationRequestOutcome()
}
