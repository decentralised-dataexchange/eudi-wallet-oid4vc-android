package com.ewc.eudi_wallet_oidc_android.services.issue.token

import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletAttestation
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletUnitAttestationHeaders

/**
 * The token request body, assembled once.
 *
 * Blank values are **omitted rather than sent empty**, matching
 * `AuthorizationRequestParameters`. The previous implementation sent `code_verifier=` and
 * `redirect_uri=` as empty strings whenever the caller had none, which is not the same as not
 * sending them.
 */
internal data class TokenRequestParameters(
    val grantType: String,
    val code: String,
    val codeVerifier: String? = null,
    val redirectUri: String? = null,
    val clientId: String? = null,
    val txCode: String? = null,
    val txCodeParameterName: String = TX_CODE,
    val authorizationDetails: String? = null,
    val resource: String? = null,
) {

    /** The body as it goes on the wire, blanks omitted. */
    fun toMap(): Map<String, String> = buildMap {
        put("grant_type", grantType)
        // The two grants name the code differently; everything else below is shared.
        when (grantType) {
            TokenGrant.PRE_AUTHORIZED_CODE -> put("pre-authorized_code", code)
            else -> put("code", code)
        }
        codeVerifier?.takeIf { it.isNotBlank() }?.let { put("code_verifier", it) }
        redirectUri?.takeIf { it.isNotBlank() }?.let { put("redirect_uri", it) }
        clientId?.takeIf { it.isNotBlank() }?.let { put("client_id", it) }
        txCode?.takeIf { it.isNotBlank() }?.let { put(txCodeParameterName, it) }
        authorizationDetails?.takeIf { it.isNotBlank() }?.let { put("authorization_details", it) }
        resource?.takeIf { it.isNotBlank() }?.let { put("resource", it) }
    }

    companion object {
        const val TX_CODE = "tx_code"

        /** What the pre-1.0 drafts called it. */
        const val USER_PIN = "user_pin"

        private const val DRAFT_VERSION = 1

        fun build(
            session: IssuanceSession,
            wallet: WalletIdentity,
            attestation: WalletAttestation?,
            grant: TokenGrant,
            authorizationDetails: String? = null,
            policy: TokenRequestPolicy = TokenRequestPolicy.Default,
        ): TokenRequestParameters {
            // The same rule the authorization request uses: the wallet unit identifier from the
            // attestation, falling back to the DID. RFC 6749 section 4.1.3 -- the two legs must
            // agree, and they did not: this request used to send the bare DID.
            val clientId = WalletUnitAttestationHeaders.clientId(attestation?.attestationJwt, wallet.did)

            return when (grant) {
                is TokenGrant.PreAuthorized -> TokenRequestParameters(
                    grantType = grant.grantType,
                    code = grant.code,
                    // Section 6.1: client authentication is OPTIONAL for this grant, and the
                    // previous implementation sent no client_id here. Unchanged.
                    clientId = null,
                    txCode = grant.txCode,
                    txCodeParameterName =
                        if (session.offerVersion == DRAFT_VERSION) USER_PIN else TX_CODE,
                    authorizationDetails = authorizationDetails.takeIf { policy.sendAuthorizationDetails },
                    resource = resourceFor(session, policy),
                )

                is TokenGrant.AuthorizationCode -> TokenRequestParameters(
                    grantType = grant.grantType,
                    code = grant.code,
                    codeVerifier = grant.codeVerifier,
                    redirectUri = grant.redirectUri,
                    clientId = clientId,
                    authorizationDetails = authorizationDetails.takeIf { policy.sendAuthorizationDetails },
                    resource = resourceFor(session, policy),
                )
            }
        }

        /**
         * The `resource` value, set only when the issuer metadata declares `authorization_servers`
         * -- the same condition sections 5.1.2 and 6.1 attach to it, and the same one that governs
         * the authorization detail's `locations`.
         */
        private fun resourceFor(session: IssuanceSession, policy: TokenRequestPolicy): String? {
            if (!policy.sendResourceParameter) return null
            val declaresAuthorizationServers =
                session.issuerConfig?.authorizationServers?.any { it.isNotBlank() } == true
            if (!declaresAuthorizationServers) return null
            return session.credentialOffer?.credentialIssuer ?: session.issuerConfig?.credentialIssuer
        }
    }
}
