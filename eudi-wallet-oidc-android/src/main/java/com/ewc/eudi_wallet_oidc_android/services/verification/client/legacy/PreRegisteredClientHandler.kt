package com.ewc.eudi_wallet_oidc_android.services.verification.client.legacy

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.client.ClientIdPrefix
import com.ewc.eudi_wallet_oidc_android.services.verification.client.ClientIdentifier
import com.ewc.eudi_wallet_oidc_android.services.verification.client.ClientIdentifierHandler
import com.ewc.eudi_wallet_oidc_android.services.verification.client.VerifierIdentity
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestException
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy

/**
 * Section 5.9.2: a client id with no colon "MUST" be treated as a pre-registered client, and one
 * with an unrecognised prefix "can" be. The draft `https` scheme lands here too. The SDK has no
 * client registry, so such a request is let through unverified while the policy allows it; the
 * host's own trust list is what vouches for the client.
 *
 * LEGACY in spirit: once every verifier sends a 1.0 prefix this handler can refuse by default.
 */
class PreRegisteredClientHandler : ClientIdentifierHandler {

    override val prefixes = setOf(ClientIdPrefix.PRE_REGISTERED, ClientIdPrefix.HTTPS)

    override suspend fun verify(request: PresentationRequest, identifier: ClientIdentifier, policy: PresentationRequestPolicy): VerifierIdentity {
        if (!policy.allowPreRegisteredClients) {
            throw PresentationRequestException.ClientNotVerified(
                identifier.unrecognisedPrefix?.let { "the client identifier prefix '$it' is not supported" }
                    ?: "pre-registered clients are not accepted"
            )
        }
        return VerifierIdentity(
            identifier = identifier,
            verified = false,
            reason = identifier.unrecognisedPrefix?.let { "unrecognised prefix '$it', treated as a pre-registered client" }
                ?: "pre-registered client; the request carries no authentication",
        )
    }
}
