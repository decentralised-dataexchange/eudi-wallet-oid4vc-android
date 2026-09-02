package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata

import com.ewc.eudi_wallet_oidc_android.models.AuthorizationCode
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.Grants
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.PreAuthorizationCode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/** OpenID4VCI 1.0 section 12.2.4 and the `authorization_server` grant parameter. */
class AuthorizationServerSelectorTest {

    private val selector = AuthorizationServerSelector()

    private fun issuer(
        credentialIssuer: String? = "https://issuer.example.com",
        singular: String? = null,
        servers: List<String>? = null,
        declaredIssuer: String? = null,
    ) = IssuerWellKnownConfiguration(
        issuer = declaredIssuer,
        credentialIssuer = credentialIssuer,
        authorizationServer = singular,
        authorizationServers = servers?.let { ArrayList(it) },
    )

    @Test
    fun `absent authorization_servers makes the credential issuer its own authorization server`() {
        val selection = selector.select(issuer())
        assertEquals("https://issuer.example.com", selection.identifier)
        assertEquals(AuthorizationServerSource.CredentialIssuer, selection.source)
    }

    /**
     * Preserves what hosts implementing this themselves have always done: a draft-era `issuer`
     * outranks the Credential Issuer Identifier when no authorization server is declared.
     */
    @Test
    fun `a draft issuer parameter is preferred over the credential issuer`() {
        val selection = selector.select(issuer(declaredIssuer = "https://as.example.com"))
        assertEquals("https://as.example.com", selection.identifier)
        assertEquals(AuthorizationServerSource.IssuerParameter, selection.source)
    }

    @Test
    fun `an explicit authorization server still outranks the issuer parameter`() {
        val selection = selector.select(
            issuer(declaredIssuer = "https://other.example.com", servers = listOf("https://as.example.com"))
        )
        assertEquals("https://as.example.com", selection.identifier)
        assertEquals(AuthorizationServerSource.SoleEntry, selection.source)
    }

    @Test
    fun `the draft singular parameter is used when present`() {
        val selection = selector.select(issuer(singular = "https://as.ebsi.example/auth-mock"))
        assertEquals("https://as.ebsi.example/auth-mock", selection.identifier)
        assertEquals(AuthorizationServerSource.SingularParameter, selection.source)
    }

    @Test
    fun `a single entry is used`() {
        val selection = selector.select(issuer(servers = listOf("https://as.example.com")))
        assertEquals("https://as.example.com", selection.identifier)
        assertEquals(AuthorizationServerSource.SoleEntry, selection.source)
    }

    @Test
    fun `a matching offer hint picks its entry out of several`() {
        val selection = selector.select(
            issuer(servers = listOf("https://as-a.example.com", "https://as-b.example.com")),
            hint = "https://as-b.example.com",
        )
        assertEquals("https://as-b.example.com", selection.identifier)
        assertEquals(AuthorizationServerSource.OfferHint, selection.source)
    }

    /**
     * "the Wallet MUST NOT proceed with the flow if the authorization_server Credential Offer
     * parameter value does not match any of the entries in the authorization_servers array".
     * The wallet's own implementation silently fell back to the first entry here.
     */
    @Test
    fun `a non-matching offer hint stops the flow`() {
        val error = assertThrows(DiscoveryException.Invalid::class.java) {
            selector.select(
                issuer(servers = listOf("https://as-a.example.com", "https://as-b.example.com")),
                hint = "https://attacker.example.com",
            )
        }
        assertEquals(true, error.message?.contains("does not list"))
    }

    @Test
    fun `a non-matching hint against a single entry also stops the flow`() {
        assertThrows(DiscoveryException.Invalid::class.java) {
            selector.select(issuer(servers = listOf("https://as-a.example.com")), hint = "https://other.example.com")
        }
    }

    @Test
    fun `several entries and no hint take the first`() {
        val selection = selector.select(
            issuer(servers = listOf("https://as-a.example.com", "https://as-b.example.com"))
        )
        assertEquals("https://as-a.example.com", selection.identifier)
        assertEquals(AuthorizationServerSource.FirstOfSeveral, selection.source)
        assertEquals(2, selection.candidates.size)
    }

    @Test
    fun `an empty array with no credential issuer is rejected`() {
        assertThrows(DiscoveryException.Invalid::class.java) {
            selector.select(issuer(credentialIssuer = null, servers = emptyList()))
        }
    }

    @Test
    fun `the hint is read from the authorization code grant`() {
        val offer = CredentialOffer(
            grants = Grants(
                authorizationCode = AuthorizationCode(authorizationServer = "https://as-b.example.com")
            )
        )
        assertEquals("https://as-b.example.com", selector.hintFrom(offer))
    }

    @Test
    fun `the hint is read from the pre-authorized grant`() {
        val offer = CredentialOffer(
            grants = Grants(
                preAuthorizationCode = PreAuthorizationCode(authorizationServer = "https://as-c.example.com")
            )
        )
        assertEquals("https://as-c.example.com", selector.hintFrom(offer))
    }

    /** Issuers have been seen sending a single-element array where the spec says string. */
    @Test
    fun `the hint tolerates an array`() {
        val offer = CredentialOffer(
            grants = Grants(
                authorizationCode = AuthorizationCode(authorizationServer = listOf("https://as-b.example.com"))
            )
        )
        assertEquals("https://as-b.example.com", selector.hintFrom(offer))
    }

    @Test
    fun `no grants means no hint`() {
        assertNull(selector.hintFrom(CredentialOffer()))
        assertNull(selector.hintFrom(null))
    }
}
