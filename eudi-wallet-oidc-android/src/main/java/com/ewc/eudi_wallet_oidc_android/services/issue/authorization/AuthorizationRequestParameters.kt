package com.ewc.eudi_wallet_oidc_android.services.issue.authorization

import com.ewc.eudi_wallet_oidc_android.models.ClientMetaDataas
import com.ewc.eudi_wallet_oidc_android.models.Jwt
import com.ewc.eudi_wallet_oidc_android.models.VpFormatsSupported
import com.ewc.eudi_wallet_oidc_android.services.codeVerifier.CodeVerifierService
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletUnitAttestationHeaders
import com.google.gson.Gson
import java.util.UUID

/**
 * The authorization request parameters, assembled once.
 *
 * Previously each of the four transports built this same set in its own literal map, so a change to
 * the request shape had to be made four times -- and three of the four had already drifted.
 *
 * Blank values are **omitted rather than sent empty**. `issuer_state ?: ""` used to put an empty
 * parameter on every request that had no issuer state, which some authorization servers reject;
 * section 4.1.1 requires including it only when the offer carried one.
 */
data class AuthorizationRequestParameters(
    val responseType: String,
    val scope: String,
    val state: String,
    val clientId: String,
    val authorizationDetails: String,
    val redirectUri: String,
    val nonce: String,
    val codeChallenge: String?,
    val codeChallengeMethod: String,
    val clientMetadata: String?,
    val issuerState: String?,
    /** RFC 8707, naming the Credential Issuer when an authorization server serves several. */
    val resource: String?,
) {

    /** Form or query parameters, with anything blank left out. */
    fun toMap(): Map<String, String> = buildMap {
        put("response_type", responseType)
        put("scope", scope)
        put("state", state)
        put("client_id", clientId)
        put("authorization_details", authorizationDetails)
        put("redirect_uri", redirectUri)
        put("nonce", nonce)
        codeChallenge?.takeIf { it.isNotBlank() }?.let {
            put("code_challenge", it)
            put("code_challenge_method", codeChallengeMethod)
        }
        clientMetadata?.takeIf { it.isNotBlank() }?.let { put("client_metadata", it) }
        issuerState?.takeIf { it.isNotBlank() }?.let { put("issuer_state", it) }
        resource?.takeIf { it.isNotBlank() }?.let { put("resource", it) }
    }

    /** The same parameters appended to an authorization endpoint. */
    fun appendTo(endpoint: String): String =
        AuthorizationUri.appendQueryParameters(endpoint, toMap())

    companion object {

        /**
         * @param scopeTypes the credential types, used only for the `mso_mdoc` scope form.
         */
        fun build(
            session: IssuanceSession,
            wallet: WalletIdentity,
            attestation: WalletAttestation?,
            selection: CredentialSelection,
            authorizationDetails: String,
            codeVerifier: String,
            redirectUri: String?,
            scopeTypes: List<String>,
            policy: AuthorizationRequestPolicy,
        ): AuthorizationRequestParameters {
            // An mdoc request carries the doctype in the scope; everything else asks for `openid`
            // and identifies the credential through authorization_details.
            val baseScope = if (selection.format == "mso_mdoc") {
                "${scopeTypes.firstOrNull().orEmpty()} openid".trim()
            } else {
                "openid"
            }
            // Section 5.1.2: the issuer declares a scope per credential configuration. Off by
            // default -- see AuthorizationRequestPolicy.useCredentialScopes.
            val declaredScopes = if (policy.useCredentialScopes) {
                CredentialScopes.forOffer(session)
            } else {
                emptyList()
            }
            val scope = (declaredScopes + baseScope.split(" "))
                .filter { it.isNotBlank() }
                .distinct()
                .joinToString(" ")

            val redirect = redirectUri ?: DEFAULT_REDIRECT_URI

            // Not sent for mdoc, which has no VP formats to declare.
            val clientMetadata = if (!policy.sendClientMetadata || selection.format == "mso_mdoc") {
                null
            } else {
                Gson().toJson(
                    ClientMetaDataas(
                        vpFormatsSupported = VpFormatsSupported(
                            jwtVp = Jwt(arrayListOf("ES256")),
                            jwtVc = Jwt(arrayListOf("ES256")),
                        ),
                        responseTypesSupported = arrayListOf("vp_token", "id_token"),
                        authorizationEndpoint = redirect,
                    )
                )
            }

            return AuthorizationRequestParameters(
                responseType = "code",
                scope = scope,
                state = UUID.randomUUID().toString(),
                clientId = WalletUnitAttestationHeaders
                    .clientId(attestation?.attestationJwt, wallet.did)
                    .orEmpty(),
                authorizationDetails = authorizationDetails,
                redirectUri = redirect,
                nonce = UUID.randomUUID().toString(),
                codeChallenge = CodeVerifierService().generateCodeChallenge(codeVerifier),
                codeChallengeMethod = "S256",
                clientMetadata = clientMetadata,
                issuerState = session.issuerState,
                resource = resourceFor(session, policy),
            )
        }

        const val DEFAULT_REDIRECT_URI = "openid://callback"

        /**
         * The `resource` value, set only when the issuer metadata declares `authorization_servers`
         * -- the same condition sections 5.1.2 and 6.1 attach to it, and the same one that governs
         * the authorization detail's `locations`.
         */
        private fun resourceFor(
            session: IssuanceSession,
            policy: AuthorizationRequestPolicy,
        ): String? {
            if (!policy.sendResourceParameter) return null
            val declaresAuthorizationServers =
                session.issuerConfig?.authorizationServers?.any { it.isNotBlank() } == true
            if (!declaresAuthorizationServers) return null
            return session.credentialOffer?.credentialIssuer
                ?: session.issuerConfig?.credentialIssuer
        }
    }
}
