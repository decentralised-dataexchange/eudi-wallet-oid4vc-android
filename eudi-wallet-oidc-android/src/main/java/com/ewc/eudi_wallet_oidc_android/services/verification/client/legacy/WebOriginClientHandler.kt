package com.ewc.eudi_wallet_oidc_android.services.verification.client.legacy

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.client.ClientIdPrefix
import com.ewc.eudi_wallet_oidc_android.services.verification.client.ClientIdentifier
import com.ewc.eudi_wallet_oidc_android.services.verification.client.ClientIdentifierHandler
import com.ewc.eudi_wallet_oidc_android.services.verification.client.VerifierIdentity
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy

/**
 * LEGACY, draft `web-origin`: the Digital Credentials API origin, which the platform
 * authenticates before the request reaches the wallet. Nothing in the request itself can be
 * checked here; the host's DC API trust check owns this case.
 */
class WebOriginClientHandler : ClientIdentifierHandler {

    override val prefixes = setOf(ClientIdPrefix.WEB_ORIGIN)

    override suspend fun verify(request: PresentationRequest, identifier: ClientIdentifier, policy: PresentationRequestPolicy): VerifierIdentity =
        VerifierIdentity(identifier = identifier, verified = false, reason = "web-origin is authenticated by the platform, not by the request")
}
