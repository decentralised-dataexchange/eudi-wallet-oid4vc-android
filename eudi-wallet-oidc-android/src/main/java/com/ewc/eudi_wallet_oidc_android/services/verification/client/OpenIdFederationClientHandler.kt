package com.ewc.eudi_wallet_oidc_android.services.verification.client

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestException
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy

/**
 * Section 5.9.3 `openid_federation`: "Processing rules given in [OpenID.Federation] MUST be
 * followed." This SDK does not implement OpenID Federation, so the prefix is not advertised and
 * a request using it is refused rather than let through unverified.
 */
class OpenIdFederationClientHandler : ClientIdentifierHandler {

    override val prefixes = setOf(ClientIdPrefix.OPENID_FEDERATION)

    override fun supported(policy: PresentationRequestPolicy): Boolean = false

    override suspend fun verify(request: PresentationRequest, identifier: ClientIdentifier, policy: PresentationRequestPolicy): VerifierIdentity =
        throw PresentationRequestException.UnsupportedClientIdPrefix("openid_federation")
}
