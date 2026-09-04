package com.ewc.eudi_wallet_oidc_android.services.issue.authorization

import com.ewc.eudi_wallet_oidc_android.models.AuthorizationCode
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.Credentials
import com.ewc.eudi_wallet_oidc_android.models.Grants
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The parameter set every transport shares. It used to be built four times, once per branch.
 */
class AuthorizationRequestParametersTest {

    private fun session(issuerState: String? = null) = IssuanceSession(
        credentialOffer = CredentialOffer(
            credentialIssuer = "https://issuer.example.com",
            grants = issuerState?.let { Grants(authorizationCode = AuthorizationCode(issuerState = it)) },
        ),
        issuerConfig = null,
        authConfig = null,
    )

    private fun build(
        session: IssuanceSession = session(),
        selection: CredentialSelection = CredentialSelection(format = "jwt_vc_json"),
        policy: AuthorizationRequestPolicy = AuthorizationRequestPolicy.Default,
        codeVerifier: String = "a".repeat(64),
    ) = AuthorizationRequestParameters.build(
        session = session,
        wallet = WalletIdentity(did = "did:key:zabc", jwk = null),
        attestation = null,
        selection = selection,
        authorizationDetails = "[]",
        codeVerifier = codeVerifier,
        redirectUri = null,
        scopeTypes = listOf("org.iso.18013.5.1.mDL"),
        policy = policy,
    )

    @Test
    fun `the shared parameters are present`() {
        val map = build().toMap()
        assertEquals("code", map["response_type"])
        assertEquals("openid", map["scope"])
        assertEquals("[]", map["authorization_details"])
        assertEquals(AuthorizationRequestParameters.DEFAULT_REDIRECT_URI, map["redirect_uri"])
        assertTrue(map.containsKey("state"))
        assertTrue(map.containsKey("nonce"))
    }

    /**
     * Section 4.1.1 requires `issuer_state` only when the offer carried one. It used to be sent as
     * an empty string on every request that had none, which some authorization servers reject.
     */
    @Test
    fun `issuer_state is sent when the offer carried one and omitted otherwise`() {
        assertEquals("abc123", build(session(issuerState = "abc123")).toMap()["issuer_state"])
        assertFalse(build(session(issuerState = null)).toMap().containsKey("issuer_state"))
        assertFalse(build(session(issuerState = "  ")).toMap().containsKey("issuer_state"))
    }

    @Test
    fun `code_challenge_method is only sent alongside a challenge`() {
        val map = build().toMap()
        assertTrue(map.containsKey("code_challenge"))
        assertEquals("S256", map["code_challenge_method"])
    }

    /** An mdoc request carries the doctype in the scope and declares no VP formats. */
    @Test
    fun `mso_mdoc uses the doctype scope and sends no client_metadata`() {
        val map = build(selection = CredentialSelection(format = "mso_mdoc")).toMap()
        assertEquals("org.iso.18013.5.1.mDL openid", map["scope"])
        assertFalse(map.containsKey("client_metadata"))
    }

    @Test
    fun `client_metadata is sent for other formats and can be turned off`() {
        assertTrue(build().toMap().containsKey("client_metadata"))
        assertFalse(build(policy = AuthorizationRequestPolicy.Strict).toMap().containsKey("client_metadata"))
    }

    @Test
    fun `appendTo builds a query on the authorization endpoint`() {
        val url = build().appendTo("https://as.example.com/authorize")
        assertTrue(url.startsWith("https://as.example.com/authorize?"))
        assertTrue(url.contains("response_type=code"))
    }

    // MARK: - resource and scope, sections 5.1.2 and 5.1.3

    private fun sessionWith(
        authorizationServers: List<String>?,
        supported: Map<String, Map<String, String>>? = null,
    ) = IssuanceSession(
        credentialOffer = CredentialOffer(
            credentialIssuer = "https://issuer.example.com",
            credentials = arrayListOf(Credentials(types = arrayListOf("PidSdJwt"))),
            version = 2,
        ),
        issuerConfig = IssuerWellKnownConfiguration(
            credentialIssuer = "https://issuer.example.com",
            authorizationServers = authorizationServers?.let { ArrayList(it) },
            credentialsSupported = supported,
        ),
        authConfig = null,
    )

    /**
     * "If the Credential Issuer metadata contains an authorization_servers property, it is
     * RECOMMENDED to use a resource parameter [RFC8707] whose value is the Credential Issuer's
     * identifier value." Never sent before.
     */
    @Test
    fun `resource is sent only when the issuer declares authorization servers`() {
        val withServers = build(sessionWith(listOf("https://as.example.com"))).toMap()
        assertEquals("https://issuer.example.com", withServers["resource"])

        assertFalse(build(sessionWith(null)).toMap().containsKey("resource"))
        assertFalse(build(sessionWith(emptyList())).toMap().containsKey("resource"))
    }

    @Test
    fun `resource can be turned off by policy`() {
        val policy = AuthorizationRequestPolicy.Default.copy(sendResourceParameter = false)
        val map = build(sessionWith(listOf("https://as.example.com")), policy = policy).toMap()
        assertFalse(map.containsKey("resource"))
    }

    /**
     * Section 5.1.2 says to take the scope from the credential configuration. Off by default,
     * because it changes a parameter the authorization server acts on rather than adding one it
     * must ignore.
     */
    @Test
    fun `the declared credential scope is used only when enabled`() {
        val session = sessionWith(null, supported = mapOf("PidSdJwt" to mapOf("scope" to "pid.read")))

        assertEquals("openid", build(session).toMap()["scope"])

        val policy = AuthorizationRequestPolicy.Default.copy(useCredentialScopes = true)
        assertEquals("pid.read openid", build(session, policy = policy).toMap()["scope"])
    }

    @Test
    fun `a configuration with no declared scope falls back to openid`() {
        val session = sessionWith(null, supported = mapOf("PidSdJwt" to mapOf("format" to "dc+sd-jwt")))
        val policy = AuthorizationRequestPolicy.Default.copy(useCredentialScopes = true)
        assertEquals("openid", build(session, policy = policy).toMap()["scope"])
    }
}
