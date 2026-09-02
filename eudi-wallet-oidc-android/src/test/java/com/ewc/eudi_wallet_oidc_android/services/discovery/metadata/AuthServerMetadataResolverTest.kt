package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata

import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class AuthServerMetadataResolverTest {

    private lateinit var server: MockWebServer

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    private val oauthInsertion = "/.well-known/oauth-authorization-server/auth"
    private val oidcInsertion = "/.well-known/openid-configuration/auth"
    private val oidcSuffix = "/auth/.well-known/openid-configuration"

    private fun identifier() = server.url("/auth").toString().trimEnd('/')

    private fun metadata(issuer: String = identifier()) = """
        {
          "issuer": "$issuer",
          "authorization_endpoint": "$issuer/authorize",
          "token_endpoint": "$issuer/token",
          "jwks_uri": "$issuer/jwks",
          "grant_types_supported": ["authorization_code"]
        }
    """.trimIndent()

    private fun serve(vararg responses: Pair<String, MockResponse>) {
        val byPath = responses.toMap()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse =
                byPath[request.path] ?: MockResponse().setResponseCode(404)
        }
    }

    private fun json(body: String) = MockResponse()
        .setResponseCode(200)
        .setHeader("Content-Type", "application/json")
        .setBody(body)

    private fun httpAllowed(policy: DiscoveryPolicy) = policy.copy(allowedSchemes = setOf("http", "https"))

    private fun resolve(
        policy: DiscoveryPolicy = httpAllowed(DiscoveryPolicy.Default),
        verifier: SignedMetadataVerifier = RejectingSignedMetadataVerifier(),
        input: String = identifier(),
    ) = runBlocking {
        AuthServerMetadataResolver(policy = policy, signedMetadataVerifier = verifier).resolve(input)
    }

    /** Section 12.2.4 names the oauth-authorization-server location; it must be asked first. */
    @Test
    fun `the rfc8414 location is tried first`() {
        serve(oauthInsertion to json(metadata()))

        val result = resolve()

        assertNotNull(result.response.authConfig)
        assertEquals(WellKnownUrlBuilder.OAUTH_AUTHORIZATION_SERVER, result.diagnostics.wellKnown)
        assertFalse(result.diagnostics.usedOpenIdConfigurationFallback)
        assertEquals(oauthInsertion, server.takeRequest().path)
    }

    /** EBSI's authorization server: oauth-authorization-server 404s, openid-configuration answers. */
    @Test
    fun `openid-configuration answers when the rfc8414 location is missing`() {
        serve(oidcSuffix to json(metadata()))

        val result = resolve()

        assertNotNull(result.response.authConfig)
        assertEquals(WellKnownUrlBuilder.OPENID_CONFIGURATION, result.diagnostics.wellKnown)
        assertTrue(result.diagnostics.usedOpenIdConfigurationFallback)
    }

    @Test
    fun `the openid-configuration insertion form is tried before either suffix form`() {
        serve(oidcInsertion to json(metadata()))

        val result = resolve()

        assertNotNull(result.response.authConfig)
        assertEquals(WellKnownForm.Insertion, result.diagnostics.form)
        assertEquals(2, result.diagnostics.attemptedUrls.size)
    }

    @Test
    fun `strict policy asks only the rfc8414 location`() {
        serve(oidcSuffix to json(metadata()))

        val result = resolve(policy = httpAllowed(DiscoveryPolicy.Strict))

        assertNull(result.response.authConfig)
        assertEquals(1, result.diagnostics.attemptedUrls.size)
    }

    @Test
    fun `a definite error outranks a 404 from a later url`() {
        serve(oauthInsertion to MockResponse().setResponseCode(500).setBody("boom"))

        val result = resolve()

        assertNull(result.response.authConfig)
        assertEquals(500, result.response.errorResponse?.error)
    }

    @Test
    fun `signed metadata is rejected rather than decoded`() {
        val unsignedJwt = "eyJhbGciOiJub25lIn0.eyJ0b2tlbl9lbmRwb2ludCI6Imh0dHBzOi8vYXR0YWNrZXIifQ."
        serve(oauthInsertion to MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/jwt")
            .setBody(unsignedJwt))

        val result = resolve()

        assertNull(result.response.authConfig)
        assertTrue(result.response.errorResponse?.errorDescription!!.contains("cannot verify"))
    }

    @Test
    fun `a document with no token endpoint is rejected`() {
        serve(oauthInsertion to json("""{"issuer": "${identifier()}"}"""))

        val result = resolve()

        assertNull(result.response.authConfig)
        assertTrue(result.response.errorResponse?.errorDescription!!.contains("token endpoint"))
    }

    /** RFC 8414 mandates response_types_supported; OpenID4VCI explicitly allows omitting it. */
    @Test
    fun `a pre-authorized-only server omitting response_types_supported is accepted`() {
        serve(oauthInsertion to json("""
            {
              "issuer": "${identifier()}",
              "token_endpoint": "${identifier()}/token",
              "grant_types_supported": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
            }
        """.trimIndent()))

        assertNotNull(resolve().response.authConfig)
    }

    /** The wallet passes a full well-known URL; it must be stripped, not appended to. */
    @Test
    fun `a full well-known url is accepted as the identifier`() {
        serve(oauthInsertion to json(metadata()))

        val result = resolve(input = "${identifier()}/.well-known/oauth-authorization-server")

        assertNotNull(result.response.authConfig)
        assertEquals(identifier(), result.diagnostics.identifier)
    }

    @Test
    fun `a blank address reports an error rather than returning null`() {
        val result = runBlocking { AuthServerMetadataResolver().resolve(null) }
        assertNull(result.response.authConfig)
        assertNotNull(result.response.errorResponse?.errorDescription)
    }
}
