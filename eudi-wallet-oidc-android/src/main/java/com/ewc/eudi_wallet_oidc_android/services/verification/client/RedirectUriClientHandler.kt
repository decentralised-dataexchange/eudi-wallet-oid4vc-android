package com.ewc.eudi_wallet_oidc_android.services.verification.client

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.ResponseModes
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy
import com.ewc.eudi_wallet_oidc_android.services.verification.request.RequestObjectParser

/**
 * Section 5.9.3 `redirect_uri`: "the original Client Identifier part is the Verifier's Redirect
 * URI (or Response URI when Response Mode direct_post is used). The Verifier MAY omit the
 * redirect_uri Authorization Request parameter." And: "Requests using the redirect_uri Client
 * Identifier Prefix cannot be signed because there is no method for the Wallet to obtain a
 * trusted key for verification."
 *
 * So there is nothing to verify. The identifier fills in the missing URI, and a signature, if a
 * verifier sent one anyway, is ignored and said so.
 */
class RedirectUriClientHandler : ClientIdentifierHandler {

    override val prefixes = setOf(ClientIdPrefix.REDIRECT_URI)

    override suspend fun verify(request: PresentationRequest, identifier: ClientIdentifier, policy: PresentationRequestPolicy): VerifierIdentity {
        val mode = request.responseMode?.let { ResponseModes.fromString(it) }
        if (mode == ResponseModes.DIRECT_POST || mode == ResponseModes.DIRECT_POST_JWT) {
            if (request.responseUri.isNullOrBlank()) request.responseUri = identifier.identifier
        } else {
            if (request.redirectUri.isNullOrBlank()) request.redirectUri = identifier.identifier
        }

        val signed = request.request?.let { RequestObjectParser.looksLikeJwt(it) && !RequestObjectParser.isUnsigned(it) } == true
        return VerifierIdentity(
            identifier = identifier,
            verified = false,
            reason = if (signed) "a redirect_uri request cannot be verified; its signature was ignored"
            else "the redirect_uri prefix carries no authentication",
        )
    }
}
