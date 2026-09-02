package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * OpenID4VCI 1.0 section 12.2.2 and RFC 8414 section 3 both insert the well-known string between
 * the host and the path. The two worked examples below are the spec's own.
 */
class WellKnownUrlBuilderTest {

    private val wellKnown = WellKnownUrlBuilder.OPENID_CREDENTIAL_ISSUER

    @Test
    fun `insertion form places the well-known between host and path`() {
        assertEquals(
            "https://issuer.example.com/.well-known/openid-credential-issuer/tenant",
            WellKnownUrlBuilder.insertionForm("https://issuer.example.com/tenant", wellKnown),
        )
    }

    @Test
    fun `insertion form on a bare host appends only`() {
        assertEquals(
            "https://tenant.issuer.example.com/.well-known/openid-credential-issuer",
            WellKnownUrlBuilder.insertionForm("https://tenant.issuer.example.com", wellKnown),
        )
    }

    @Test
    fun `insertion form keeps the port`() {
        assertEquals(
            "http://localhost:8080/.well-known/openid-credential-issuer/tenant",
            WellKnownUrlBuilder.insertionForm("http://localhost:8080/tenant", wellKnown),
        )
    }

    @Test
    fun `insertion form rejects a value that is not an absolute url`() {
        assertNull(WellKnownUrlBuilder.insertionForm("not a url", wellKnown))
        assertNull(WellKnownUrlBuilder.insertionForm("/tenant", wellKnown))
    }

    @Test
    fun `suffix form appends`() {
        assertEquals(
            "https://issuer.example.com/tenant/.well-known/openid-credential-issuer",
            WellKnownUrlBuilder.suffixForm("https://issuer.example.com/tenant", wellKnown),
        )
    }

    @Test
    fun `identifier strips a suffix-form well-known`() {
        assertEquals(
            "https://issuer.example.com/tenant",
            WellKnownUrlBuilder.identifier("https://issuer.example.com/tenant/.well-known/openid-credential-issuer"),
        )
    }

    @Test
    fun `identifier strips an insertion-form well-known`() {
        assertEquals(
            "https://issuer.example.com/tenant",
            WellKnownUrlBuilder.identifier("https://issuer.example.com/.well-known/openid-credential-issuer/tenant"),
        )
    }

    @Test
    fun `identifier strips both authorization server well-knowns`() {
        assertEquals(
            "https://as.example.com",
            WellKnownUrlBuilder.identifier("https://as.example.com/.well-known/oauth-authorization-server"),
        )
        assertEquals(
            "https://as.example.com",
            WellKnownUrlBuilder.identifier("https://as.example.com/.well-known/openid-configuration"),
        )
    }

    @Test
    fun `identifier strips a trailing slash`() {
        assertEquals("https://issuer.example.com", WellKnownUrlBuilder.identifier("https://issuer.example.com/"))
    }

    @Test
    fun `identifier rejects blank input`() {
        assertNull(WellKnownUrlBuilder.identifier(null))
        assertNull(WellKnownUrlBuilder.identifier("   "))
    }

    @Test
    fun `candidates try the spec form first`() {
        val candidates = WellKnownUrlBuilder.candidates(
            "https://issuer.example.com/tenant",
            wellKnown,
            DiscoveryPolicy.Default,
        )
        assertEquals(2, candidates.size)
        assertEquals("https://issuer.example.com/.well-known/openid-credential-issuer/tenant", candidates[0])
        assertEquals("https://issuer.example.com/tenant/.well-known/openid-credential-issuer", candidates[1])
    }

    @Test
    fun `candidates collapse to one when the identifier has no path`() {
        val candidates = WellKnownUrlBuilder.candidates(
            "https://issuer.example.com",
            wellKnown,
            DiscoveryPolicy.Default,
        )
        assertEquals(listOf("https://issuer.example.com/.well-known/openid-credential-issuer"), candidates)
    }

    @Test
    fun `strict policy offers only the spec form`() {
        val candidates = WellKnownUrlBuilder.candidates(
            "https://issuer.example.com/tenant",
            wellKnown,
            DiscoveryPolicy.Strict,
        )
        assertEquals(1, candidates.size)
        assertTrue(candidates.single().contains("/.well-known/openid-credential-issuer/tenant"))
    }
}
