package com.ewc.eudi_wallet_oidc_android.services.verification.client

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.client.legacy.PreRegisteredClientHandler
import com.ewc.eudi_wallet_oidc_android.services.verification.client.legacy.WebOriginClientHandler
import com.ewc.eudi_wallet_oidc_android.services.verification.client.legacy.X509SanUriClientHandler
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestException
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy

/**
 * Picks the handler for the request's client identifier prefix and runs it (OpenID4VP 1.0
 * section 5.9). Called once per request from the resolver, after the parameters are complete.
 *
 * Under [ClientVerification.Enforced] a broken rule refuses the request. Under
 * [ClientVerification.Audit] the same checks run, and a failure is logged and reported in the
 * returned [VerifierIdentity] instead.
 */
class ClientIdentifierVerifier(
    private val handlers: List<ClientIdentifierHandler> = defaultHandlers(),
) {

    suspend fun verify(request: PresentationRequest, policy: PresentationRequestPolicy): VerifierIdentity {
        val clientId = request.clientId?.takeIf { it.isNotBlank() }
        val parsed = ClientIdentifier.parse(clientId ?: "", request.clientIdScheme)

        if (policy.clientVerification == ClientVerification.Off) {
            return VerifierIdentity(parsed, verified = false, reason = "client verification is off")
        }
        return try {
            check(clientId, parsed, request, policy)
        } catch (e: PresentationRequestException) {
            if (policy.clientVerification == ClientVerification.Enforced) throw e
            Logger.w(TAG, "Client identity not verified (audit): ${e.message}")
            VerifierIdentity(parsed, verified = false, reason = e.message)
        }
    }

    private suspend fun check(
        clientId: String?,
        identifier: ClientIdentifier,
        request: PresentationRequest,
        policy: PresentationRequestPolicy,
    ): VerifierIdentity {
        if (clientId == null) throw PresentationRequestException.ClientNotVerified("the request carries no client_id")
        if (identifier.prefix == ClientIdPrefix.ORIGIN) {
            // Section 5.9.3: "The Wallet MUST NOT accept this Client Identifier Prefix in requests."
            throw PresentationRequestException.ClientNotVerified("the origin prefix is reserved for the Digital Credentials API")
        }
        val handler = handlers.firstOrNull { identifier.prefix in it.prefixes }
            ?: throw PresentationRequestException.UnsupportedClientIdPrefix(identifier.prefix.value ?: "")
        val identity = handler.verify(request, identifier, policy)
        if (policy.requireAnchoredClients && identity.verified && !identity.anchored) {
            throw PresentationRequestException.ClientNotVerified(
                identity.reason ?: "the verifier's key does not chain to a configured trust anchor"
            )
        }
        Logger.d(TAG, "Client ${identifier.original}: verified=${identity.verified} anchored=${identity.anchored}${identity.reason?.let { " ($it)" } ?: ""}")
        return identity
    }

    /**
     * The values for `wallet_metadata.client_id_prefixes_supported` (section 5.10): the 1.0
     * prefixes this registry can verify under [policy]. Derived here so the advertisement and the
     * enforcement cannot drift apart.
     */
    fun supportedPrefixes(policy: PresentationRequestPolicy): List<String> =
        handlers.filter { it.supported(policy) }
            .flatMap { it.prefixes }
            .filter { !it.legacy && it != ClientIdPrefix.PRE_REGISTERED && it != ClientIdPrefix.ORIGIN }
            .mapNotNull { it.value }
            .distinct()

    companion object {
        private const val TAG = "ClientIdentifierVerifier"

        /** Ordered: 1.0 prefixes first, legacy last. */
        fun defaultHandlers(): List<ClientIdentifierHandler> = listOf(
            RedirectUriClientHandler(),
            X509SanDnsClientHandler(),
            X509HashClientHandler(),
            DecentralizedIdentifierClientHandler(),
            VerifierAttestationClientHandler(),
            OpenIdFederationClientHandler(),
            // --- legacy, safe to delete as a block ---
            PreRegisteredClientHandler(),
            WebOriginClientHandler(),
            X509SanUriClientHandler(),
        )
    }
}
