package com.ewc.eudi_wallet_oidc_android.services.issue.offer

import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.URLEncoder

/**
 * End to end: pick a source, retrieve, pick a parser, validate.
 *
 * The `credential_offer_uri` path drives the real Retrofit/OkHttp stack against MockWebServer --
 * possible with no production change because every endpoint uses an absolute @Url.
 *
 * Every case asserts the contract that matters most to callers: a failure is always a
 * WrappedCredentialOffer carrying an errorResponse, never a bare null and never an empty wrapper.
 * The wallet's error branch keys on exactly that, and previously never fired.
 */
class CredentialOfferResolverTest {

    private lateinit var server: MockWebServer
    private val resolver = CredentialOfferResolver()

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @After
    fun tearDown() = server.shutdown()

    private fun encode(value: String) = URLEncoder.encode(value, "UTF-8")

    private fun inlineLink(offerJson: String) =
        "openid-credential-offer://?credential_offer=${encode(offerJson)}"

    private fun uriLink(path: String = "/offer") =
        "openid-credential-offer://?credential_offer_uri=${encode(server.url(path).toString())}"

    private val v1_0Offer = """
        {"credential_issuer":"https://issuer.example",
         "credential_configuration_ids":["PID"],
         "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"PRE-1"}}}
    """.trimIndent()

    private fun jsonResponse(body: String, code: Int = 200, contentType: String = "application/json") =
        MockResponse().setResponseCode(code).setHeader("Content-Type", contentType).setBody(body)

    // ── inline ──────────────────────────────────────────────────────────────

    @Test
    fun `an inline 1_0 offer resolves`() {
        val result = runBlocking { resolver.resolve(inlineLink(v1_0Offer)) }

        assertNull(result.errorResponse)
        assertEquals("https://issuer.example", result.credentialOffer?.credentialIssuer)
        assertEquals(2, result.credentialOffer?.version)
        assertEquals("PRE-1", result.credentialOffer?.grants?.preAuthorizationCode?.preAuthorizedCode)
    }

    @Test
    fun `an inline draft offer resolves and is marked as version 1`() {
        val draft = """{"credential_issuer":"https://issuer.example","credentials":["PID"]}"""
        val result = runBlocking { resolver.resolve(inlineLink(draft)) }

        assertNull(result.errorResponse)
        assertEquals(1, result.credentialOffer?.version)
    }

    @Test
    fun `any outer scheme is accepted, since wallets are launched by many of them`() {
        val result = runBlocking { resolver.resolve("haip://?credential_offer=${encode(v1_0Offer)}") }
        assertNotNull(result.credentialOffer)
    }

    // ── credential_offer_uri ────────────────────────────────────────────────

    @Test
    fun `a remote offer is fetched with GET and an Accept header`() {
        server.enqueue(jsonResponse(v1_0Offer))

        val result = runBlocking { resolver.resolve(uriLink()) }

        assertNull(result.errorResponse)
        assertEquals("https://issuer.example", result.credentialOffer?.credentialIssuer)

        val request = server.takeRequest()
        assertEquals("GET", request.method)
        assertEquals("/offer", request.path)
        assertTrue(request.getHeader("Accept")!!.contains("application/json"))
    }

    @Test
    fun `a 404 is reported rather than silently swallowed`() {
        server.enqueue(jsonResponse("""{"error":"not_found"}""", code = 404))

        val result = runBlocking { resolver.resolve(uriLink()) }

        assertNull(result.credentialOffer)
        assertNotNull(result.errorResponse)
    }

    @Test
    fun `a 500 is reported`() {
        server.enqueue(MockResponse().setResponseCode(500).setBody("upstream failure"))

        val result = runBlocking { resolver.resolve(uriLink()) }
        assertNotNull(result.errorResponse)
    }

    @Test
    fun `a redirect is reported with a real message, not an empty one`() {
        // The HTTP client does not follow redirects, so this surfaced as an error with a null
        // description and the wallet toasted an empty string.
        server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", "https://elsewhere.example"))

        val result = runBlocking { resolver.resolve(uriLink()) }

        assertNull(result.credentialOffer)
        assertTrue(result.errorResponse?.errorDescription?.isNotBlank() == true)
    }

    @Test
    fun `an empty body is reported`() {
        server.enqueue(jsonResponse(""))
        assertNotNull(runBlocking { resolver.resolve(uriLink()) }.errorResponse)
    }

    @Test
    fun `a signed offer is rejected, as the spec requires`() {
        server.enqueue(jsonResponse("eyJhbGciOiJub25lIn0.eyJhIjoxfQ.sig", contentType = "application/jwt"))

        val result = runBlocking { resolver.resolve(uriLink()) }

        assertNull(result.credentialOffer)
        assertTrue(result.errorResponse?.errorDescription?.contains("Signed", ignoreCase = true) == true)
    }

    // ── scheme policy ───────────────────────────────────────────────────────

    @Test
    fun `http is allowed by default, for local issuers`() {
        server.enqueue(jsonResponse(v1_0Offer))
        // MockWebServer serves http://
        assertNotNull(runBlocking { resolver.resolve(uriLink()) }.credentialOffer)
    }

    @Test
    fun `http is rejected under the strict policy`() {
        val strict = CredentialOfferResolver(policy = CredentialOfferPolicy.Strict)
        val result = runBlocking { strict.resolve(uriLink()) }

        assertNull(result.credentialOffer)
        assertTrue(result.errorResponse?.errorDescription?.contains("scheme", ignoreCase = true) == true)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `file and jar urls are rejected without being fetched`() {
        listOf("file:///etc/passwd", "jar:file:///tmp/x.jar!/offer.json").forEach { hostile ->
            val result = runBlocking {
                resolver.resolve("openid-credential-offer://?credential_offer_uri=${encode(hostile)}")
            }
            assertNull("expected $hostile to be rejected", result.credentialOffer)
            assertNotNull(result.errorResponse)
        }
        assertEquals(0, server.requestCount)
    }

    // ── ambiguity and absence ───────────────────────────────────────────────

    @Test
    fun `an offer carrying both mechanisms is rejected`() {
        // The spec: they MUST NOT both be present.
        val link = "openid-credential-offer://?credential_offer=${encode(v1_0Offer)}" +
            "&credential_offer_uri=${encode(server.url("/offer").toString())}"

        val result = runBlocking { resolver.resolve(link) }

        assertNull(result.credentialOffer)
        assertNotNull(result.errorResponse)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `a link with no offer is reported instead of hanging`() {
        // Previously returned Wrapped(null, null), which the wallet's if/else-if ignored entirely,
        // leaving its progress spinner running forever.
        val result = runBlocking { resolver.resolve("https://example.com/some/other/page") }

        assertNull(result.credentialOffer)
        assertNotNull(result.errorResponse)
        assertTrue(result.errorResponse?.errorDescription?.isNotBlank() == true)
    }

    @Test
    fun `null and blank input are reported, never returned as null`() {
        listOf(null, "", "   ").forEach { input ->
            val result = runBlocking { resolver.resolve(input) }
            assertNull(result.credentialOffer)
            assertNotNull("expected an error for input '$input'", result.errorResponse)
        }
    }

    // ── malformed documents ─────────────────────────────────────────────────

    @Test
    fun `an empty json object is rejected rather than parsed into an empty offer`() {
        val result = runBlocking { resolver.resolve(inlineLink("{}")) }

        assertNull(result.credentialOffer)
        assertNotNull(result.errorResponse)
    }

    @Test
    fun `malformed json, arrays and literals are rejected`() {
        listOf("{not json", "[1,2,3]", "null", "\"a string\"").forEach { body ->
            val result = runBlocking { resolver.resolve(inlineLink(body)) }
            assertNull("expected '$body' to be rejected", result.credentialOffer)
            assertNotNull(result.errorResponse)
        }
    }

    @Test
    fun `an offer with no issuer is rejected with a useful message`() {
        val result = runBlocking {
            resolver.resolve(inlineLink("""{"credential_configuration_ids":["PID"]}"""))
        }
        assertTrue(result.errorResponse?.errorDescription?.contains("issuer", ignoreCase = true) == true)
    }

    // ── version detection ───────────────────────────────────────────────────

    @Test
    fun `version is decided by shape, not by a version field on the wire`() {
        // "version" is not an OpenID4VCI field. It used to be trusted verbatim, so an issuer could
        // claim any version -- and a dual-shaped offer had its configuration ids discarded.
        val dual = """
            {"version":7,
             "credential_issuer":"https://issuer.example",
             "credential_configuration_ids":["PID"],
             "credentials":[{"format":"mso_mdoc","doctype":"org.iso.18013.5.1.mDL"}]}
        """.trimIndent()

        val result = runBlocking { resolver.resolve(inlineLink(dual)) }

        assertNull(result.errorResponse)
        // 1.0 wins over draft, and the bogus 7 is gone.
        assertEquals(2, result.credentialOffer?.version)
        assertEquals(listOf("PID"), result.credentialOffer?.credentials?.single()?.types?.toList())
    }

    @Test
    fun `draft offers can be turned off entirely`() {
        val strict = CredentialOfferResolver(policy = CredentialOfferPolicy.Strict)
        val draft = """{"credential_issuer":"https://issuer.example","credentials":["PID"]}"""

        val result = runBlocking { strict.resolve(inlineLink(draft)) }

        assertNull(result.credentialOffer)
        assertNotNull(result.errorResponse)
    }

    // ── legacy initiate_issuance ────────────────────────────────────────────

    @Test
    fun `a pre-openid4vci initiate_issuance link still resolves`() {
        val link = "openid://initiate_issuance?issuer=${encode("https://issuer.example")}" +
            "&credential_type=PortableDocumentA1" +
            "&pre-authorized_code=PRE-9&user_pin_required=true"

        val result = runBlocking { resolver.resolve(link) }

        assertNull(result.errorResponse)
        assertEquals("https://issuer.example", result.credentialOffer?.credentialIssuer)
        assertEquals(1, result.credentialOffer?.version)
        assertEquals("PRE-9", result.credentialOffer?.grants?.preAuthorizationCode?.preAuthorizedCode)
        assertNotNull(result.credentialOffer?.grants?.preAuthorizationCode?.transactionCode)
    }
}
