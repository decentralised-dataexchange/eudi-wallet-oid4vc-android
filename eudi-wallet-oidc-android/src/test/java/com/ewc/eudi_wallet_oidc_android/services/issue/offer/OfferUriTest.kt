package com.ewc.eudi_wallet_oidc_android.services.issue.offer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Query parsing for offer links, built on java.net so the offer package stays testable off-device.
 * Behaviour must match android.net.Uri.getQueryParameter, which percent-decodes and treats "+" as
 * a space.
 */
class OfferUriTest {

    @Test
    fun `reads a query parameter`() {
        assertEquals("abc", OfferUri.queryParam("openid-credential-offer://?credential_offer=abc", "credential_offer"))
    }

    @Test
    fun `percent-decodes values`() {
        val data = "openid-credential-offer://?credential_offer=%7B%22a%22%3A1%7D"
        assertEquals("""{"a":1}""", OfferUri.queryParam(data, "credential_offer"))
    }

    @Test
    fun `treats plus as space, matching Uri`() {
        assertEquals("a b", OfferUri.queryParam("x://?v=a+b", "v"))
    }

    @Test
    fun `reads a parameter that is not first`() {
        val data = "openid-credential-offer://?foo=1&credential_offer_uri=https%3A%2F%2Fx.example%2Fo"
        assertEquals("https://x.example/o", OfferUri.queryParam(data, "credential_offer_uri"))
    }

    @Test
    fun `takes the first occurrence of a repeated key`() {
        assertEquals("one", OfferUri.queryParam("x://?k=one&k=two", "k"))
    }

    @Test
    fun `a valueless parameter reads as empty, not missing`() {
        assertEquals("", OfferUri.queryParam("x://?flag", "flag"))
        assertTrue(OfferUri.hasQueryParam("x://?flag", "flag"))
    }

    @Test
    fun `ignores a fragment`() {
        assertNull(OfferUri.queryParam("x://path#credential_offer=nope", "credential_offer"))
        assertEquals("yes", OfferUri.queryParam("x://path?credential_offer=yes#frag", "credential_offer"))
    }

    @Test
    fun `missing parameters and query-less links read as null`() {
        assertNull(OfferUri.queryParam("x://path", "credential_offer"))
        assertNull(OfferUri.queryParam("", "credential_offer"))
        assertNull(OfferUri.queryParam(null, "credential_offer"))
        assertFalse(OfferUri.hasQueryParam("x://path", "credential_offer"))
    }

    @Test
    fun `malformed percent-escapes are preserved rather than throwing`() {
        assertEquals("100%", OfferUri.queryParam("x://?v=100%", "v"))
    }

    @Test
    fun `reads schemes including custom wallet schemes`() {
        assertEquals("https", OfferUri.scheme("https://x.example/o"))
        assertEquals("openid-credential-offer", OfferUri.scheme("openid-credential-offer://?a=1"))
        assertEquals("http", OfferUri.scheme("HTTP://x.example"))
        assertEquals("file", OfferUri.scheme("file:///tmp/offer.json"))
    }

    @Test
    fun `rejects things that are not schemes`() {
        assertNull(OfferUri.scheme("no-scheme-here"))
        assertNull(OfferUri.scheme("://x.example"))
        assertNull(OfferUri.scheme("9nine://x"))
        assertNull(OfferUri.scheme(""))
        assertNull(OfferUri.scheme(null))
    }
}
