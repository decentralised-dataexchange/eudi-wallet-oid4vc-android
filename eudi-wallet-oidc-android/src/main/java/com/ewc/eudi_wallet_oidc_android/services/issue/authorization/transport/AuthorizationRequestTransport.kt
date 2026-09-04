package com.ewc.eudi_wallet_oidc_android.services.issue.authorization.transport

import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationMode
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationRequestParameters
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationRequestPolicy
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationTransportKind
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity

/**
 * One way of putting an authorization request to the authorization server.
 *
 * The parameters are identical across all of them -- see
 * [AuthorizationRequestParameters] -- so a transport only decides how they travel and how the
 * answer is read. Transports are consulted in registry order, which preserves the precedence this
 * SDK has always used: the interactive extension, then PAR, then in-app, then the browser.
 */
interface AuthorizationRequestTransport {

    /** Which transport this is, reported back to the caller on every response. */
    val kind: AuthorizationTransportKind

    /** Human-readable name, used in logs. */
    val name: String

    /**
     * The URL this transport will actually send to.
     *
     * Not always the authorization endpoint: PAR posts to the pushed-authorization endpoint and the
     * interactive extension to its own. Reported as `request.endpoint` so a rejection can be traced
     * to the URL that produced it.
     */
    fun endpointFor(session: IssuanceSession): String?

    /** True when this transport is the one to use for this session. */
    fun supports(
        session: IssuanceSession,
        mode: AuthorizationMode,
        policy: AuthorizationRequestPolicy,
    ): Boolean

    /**
     * @throws com.ewc.eudi_wallet_oidc_android.services.issue.authorization.AuthorizationException
     */
    suspend fun perform(
        parameters: AuthorizationRequestParameters,
        session: IssuanceSession,
        wallet: WalletIdentity,
        headers: Map<String, String>,
        mode: AuthorizationMode,
    ): AuthorizationResponse
}
