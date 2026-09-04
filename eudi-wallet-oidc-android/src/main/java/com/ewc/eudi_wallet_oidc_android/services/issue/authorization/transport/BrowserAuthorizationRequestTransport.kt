package com.ewc.eudi_wallet_oidc_android.services.issue.authorization.transport

import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationException
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationMode
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationRequestParameters
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationRequestPolicy
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationTransportKind
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity

/**
 * The plain authorization request: build the URL and hand it to a browser.
 *
 * The default, and the last transport consulted. RFC 8252: for a scanned offer the browser must
 * make the request so the authorization server's session cookie lands there -- interactive servers
 * such as BankID depend on it.
 */
internal class BrowserAuthorizationRequestTransport : AuthorizationRequestTransport {

    override val kind = AuthorizationTransportKind.BROWSER

    override val name: String = "browser"

    override fun endpointFor(session: IssuanceSession): String? =
        session.authConfig?.authorizationEndpoint

    /** The fallback: always applicable, so it is placed last in the registry. */
    override fun supports(
        session: IssuanceSession,
        mode: AuthorizationMode,
        policy: AuthorizationRequestPolicy,
    ): Boolean = true

    override suspend fun perform(
        parameters: AuthorizationRequestParameters,
        session: IssuanceSession,
        wallet: WalletIdentity,
        headers: Map<String, String>,
        mode: AuthorizationMode,
    ): AuthorizationResponse {
        val endpoint = session.authConfig?.authorizationEndpoint
            ?: throw AuthorizationException.NoAuthorizationEndpoint()
        return AuthorizationResponse.openInBrowser(parameters.appendTo(endpoint))
    }
}
