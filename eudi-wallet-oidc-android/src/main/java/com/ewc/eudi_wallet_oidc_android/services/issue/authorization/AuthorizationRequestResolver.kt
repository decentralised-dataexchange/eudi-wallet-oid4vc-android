package com.ewc.eudi_wallet_oidc_android.services.issue.authorization

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.transport.AuthorizationRequestTransport
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.transport.BrowserAuthorizationRequestTransport
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.transport.InAppAuthorizationRequestTransport
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.transport.PushedAuthorizationRequestTransport
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.transport.extension.InteractiveAuthorizationTransport
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletUnitAttestationHeaders

/**
 * Makes the authorization request: assemble the parameters once, pick a transport, read the answer.
 *
 * The four transports previously lived as four branches of one 302-line function, each rebuilding
 * the same eleven parameters in its own literal map. They are now a registry, consulted in the same
 * precedence as before -- the interactive extension, then PAR, then in-app, then the browser -- so
 * no server that works today changes path.
 *
 * Every failure returns an [AuthorizationResponse] whose outcome is
 * [AuthorizationOutcome.FAILED], carrying a reason. A failed interactive call, an unrecognised
 * interaction type, a rejected PAR and a redirect-less response all used to end in a bare `null`.
 */
class AuthorizationRequestResolver(
    private val policy: AuthorizationRequestPolicy = AuthorizationRequestPolicy.Default,
    private val transports: List<AuthorizationRequestTransport> = defaultTransports(),
) {

    /**
     * @param authorizationDetails the `authorization_details` value, built by the caller because it
     *   depends on the credential being requested; see `IssueService.buildAuthorizationRequest`.
     * @param scopeTypes credential types, used only to form the `mso_mdoc` scope.
     */
    suspend fun resolve(
        session: IssuanceSession,
        wallet: WalletIdentity,
        attestation: WalletAttestation?,
        codeVerifier: String,
        authorizationDetails: String,
        scopeTypes: List<String>,
        selection: CredentialSelection = CredentialSelection(),
        redirectUri: String? = null,
        mode: AuthorizationMode = AuthorizationMode.Browser,
    ): AuthorizationResponse {
        val parameters = AuthorizationRequestParameters.build(
            session = session,
            wallet = wallet,
            attestation = attestation,
            selection = selection,
            authorizationDetails = authorizationDetails,
            codeVerifier = codeVerifier,
            redirectUri = redirectUri,
            scopeTypes = scopeTypes,
            policy = policy,
        )

        val headers = WalletUnitAttestationHeaders.build(
            attestation?.attestationJwt,
            attestation?.proofOfPossession,
        )

        val transport = transports.firstOrNull { it.supports(session, mode, policy) }

        // Built once and attached to every outcome, success or failure: `redirectUri` and `state`
        // are needed to finish the flow, not merely to explain it.
        val request = AuthorizationRequestInfo(
            transport = transport?.kind ?: AuthorizationTransportKind.BROWSER,
            endpoint = transport?.endpointFor(session) ?: session.authConfig?.authorizationEndpoint,
            redirectUri = parameters.redirectUri,
            state = parameters.state,
            nonce = parameters.nonce,
            sentWalletAttestation = headers.isNotEmpty(),
            parameters = parameters.toMap(),
        )

        if (transport == null) {
            return AuthorizationResponse
                .failed("No way of making an authorization request to this issuer")
                .copy(request = request)
        }

        Logger.d(TAG, "authorization request via ${transport.name}")

        return try {
            transport.perform(parameters, session, wallet, headers, mode)
        } catch (e: AuthorizationException) {
            Logger.e(TAG, "authorization request failed via ${transport.name}: ${e.message}")
            AuthorizationResponse.failed(e.toErrorResponse())
        }.copy(request = request)
    }

    companion object {
        private const val TAG = "AuthorizationRequest"

        /**
         * Ordered. The interactive extension takes precedence when the server advertises it, then
         * PAR when the server requires it, then the in-app transport when the caller asked for it,
         * and the browser last as the default.
         */
        internal fun defaultTransports(): List<AuthorizationRequestTransport> = listOf(
            // --- profile extension, not a specification feature ---
            InteractiveAuthorizationTransport(),
            PushedAuthorizationRequestTransport(),
            InAppAuthorizationRequestTransport(),
            BrowserAuthorizationRequestTransport(),
        )
    }
}
