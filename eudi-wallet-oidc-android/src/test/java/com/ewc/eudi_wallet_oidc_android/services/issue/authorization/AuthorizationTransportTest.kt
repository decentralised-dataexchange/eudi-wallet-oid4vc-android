package com.ewc.eudi_wallet_oidc_android.services.issue.authorization

import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The four transports and the precedence between them.
 *
 * Precedence is the previous implementation's -- interactive extension, PAR, in-app, browser -- and
 * is asserted here because deployed servers are distinguished only by which branch they take.
 */
class AuthorizationTransportTest {

    private lateinit var server: MockWebServer

    @Before fun setUp() { server = MockWebServer(); server.start() }
    @After fun tearDown() { server.shutdown() }

    private fun authConfig(
        interactive: String? = null,
        requirePar: Boolean = false,
    ) = AuthorisationServerWellKnownConfiguration(
        issuer = server.url("/").toString(),
        authorizationEndpoint = server.url("/authorize").toString(),
        tokenEndpoint = server.url("/token").toString(),
        pushedAuthorizationRequestEndpoint = server.url("/par").toString(),
        interactiveAuthorizationEndpoint = interactive,
        requirePushedAuthorizationRequests = requirePar,
    )

    private fun session(config: AuthorisationServerWellKnownConfiguration) = IssuanceSession(
        credentialOffer = CredentialOffer(credentialIssuer = "https://issuer.example.com"),
        issuerConfig = null,
        authConfig = config,
    )

    private fun serve(vararg responses: Pair<String, MockResponse>) {
        val byPath = responses.toMap()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse =
                byPath[request.path?.substringBefore('?')] ?: MockResponse().setResponseCode(404)
        }
    }

    private fun resolve(
        config: AuthorisationServerWellKnownConfiguration,
        mode: AuthorizationMode = AuthorizationMode.Browser,
        policy: AuthorizationRequestPolicy = AuthorizationRequestPolicy.Default,
    ) = runBlocking {
        AuthorizationRequestResolver(policy = policy).resolve(
            session = session(config),
            wallet = WalletIdentity("did:key:zabc", null),
            attestation = null,
            codeVerifier = "a".repeat(64),
            authorizationDetails = "[]",
            scopeTypes = listOf("PidSdJwt"),
            selection = CredentialSelection(format = "jwt_vc_json"),
            mode = mode,
        )
    }

    // MARK: - Precedence

    @Test
    fun `the browser transport is the default`() {
        val result = resolve(authConfig())
        assertEquals(AuthorizationOutcome.OPEN_IN_BROWSER, result.outcome)
        assertTrue(result.url!!.contains("/authorize?"))
        assertEquals(AuthorizationTransportKind.BROWSER, result.request!!.transport)
    }

    @Test
    fun `par is used when the server requires it`() {
        serve("/par" to MockResponse().setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("""{"request_uri":"urn:req:1","expires_in":90}"""))

        val result = resolve(authConfig(requirePar = true))

        assertEquals(AuthorizationOutcome.OPEN_IN_BROWSER, result.outcome)
        assertTrue(result.url!!.contains("request_uri=urn"))
        assertEquals(AuthorizationTransportKind.PUSHED, result.request!!.transport)
        // the PAR endpoint, not the authorization endpoint: the URL the request actually went to
        assertTrue(result.request!!.endpoint!!.endsWith("/par"))
        assertEquals("/par", server.takeRequest().path)
    }

    /** The interactive extension outranks PAR, as it always has. */
    @Test
    fun `the interactive extension takes precedence over par`() {
        serve("/iar" to MockResponse().setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("""{"type":"redirect_to_web","request_uri":"urn:req:2"}"""))

        val result = resolve(authConfig(interactive = server.url("/iar").toString(), requirePar = true))

        assertEquals(AuthorizationOutcome.OPEN_IN_BROWSER, result.outcome)
        assertEquals(
            AuthorizationTransportKind.INTERACTIVE_AUTHORIZATION,
            result.request!!.transport,
        )
        assertEquals("/iar", server.takeRequest().path)
    }

    @Test
    fun `the interactive extension can be turned off by policy`() {
        val result = resolve(
            authConfig(interactive = server.url("/iar").toString()),
            policy = AuthorizationRequestPolicy.Strict,
        )
        // Falls through to the browser rather than the extension.
        assertEquals(AuthorizationOutcome.OPEN_IN_BROWSER, result.outcome)
    }

    // MARK: - The interactive extension

    @Test
    fun `a presentation request becomes PresentationRequired`() {
        serve("/iar" to MockResponse().setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("""{"type":"openid4vp_presentation","status":"pending","auth_session":"sess-1",
                         "openid4vp_request":{"client_id":"x","response_type":"vp_token"}}"""))

        val result = resolve(authConfig(interactive = server.url("/iar").toString()))

        assertEquals(AuthorizationOutcome.PRESENTATION_REQUIRED, result.outcome)
        assertEquals("sess-1", result.authSession)
        assertTrue(result.url!!.contains("auth_session=sess-1"))
        assertTrue(result.url!!.contains("openid4vp_request="))
    }

    /** Both used to be logged and then fall through to a bare null. */
    @Test
    fun `an unknown interaction type and a rejected call both report a reason`() {
        serve("/iar" to MockResponse().setResponseCode(200)
            .setHeader("Content-Type", "application/json")
            .setBody("""{"type":"something_else"}"""))
        val unknown = resolve(authConfig(interactive = server.url("/iar").toString()))
        assertEquals(AuthorizationOutcome.FAILED, unknown.outcome)
        assertTrue(unknown.error!!.errorDescription!!.contains("does not support"))

        server.shutdown(); server = MockWebServer(); server.start()
        serve("/iar" to MockResponse().setResponseCode(400).setBody("bad request"))
        val rejected = resolve(authConfig(interactive = server.url("/iar").toString()))
        assertEquals(AuthorizationOutcome.FAILED, rejected.outcome)
    }

    // MARK: - PAR failures

    @Test
    fun `a rejected par reports the status instead of vanishing`() {
        serve("/par" to MockResponse().setResponseCode(400).setBody("invalid_request"))

        val result = resolve(authConfig(requirePar = true))

        assertEquals(AuthorizationOutcome.FAILED, result.outcome)
        assertEquals(400, result.error!!.httpStatus)
    }
    // MARK: - What the response carries back to the caller

    /**
     * The OAuth error code used to be lost on every PAR and IAR rejection:
     * `AuthorizationException.Rejected` accepted an `errorCode` that no call site ever passed, so a
     * well-formed error body arrived as one undifferentiated blob of text.
     */
    @Test
    fun `a rejected par keeps the oauth error code, not just the prose`() {
        serve(
            "/par" to MockResponse().setResponseCode(400).setBody(
                """{"error":"invalid_request","error_description":"redirect_uri is not registered"}"""
            )
        )

        val result = resolve(authConfig(requirePar = true))

        assertEquals(AuthorizationOutcome.FAILED, result.outcome)
        assertEquals("invalid_request", result.error!!.errorCode)
        assertEquals("redirect_uri is not registered", result.error!!.errorDescription)
        assertEquals(400, result.error!!.httpStatus)
    }

    /** RFC 9126 section 2.2. Deserialised all along, and read by nothing. */
    @Test
    fun `the par request_uri lifetime reaches the caller`() {
        serve(
            "/par" to MockResponse().setResponseCode(201)
                .setBody("""{"request_uri":"urn:ietf:params:oauth:request_uri:x","expires_in":90}""")
        )

        assertEquals(90, resolve(authConfig(requirePar = true)).expiresIn)
    }

    /** The same for the interactive extension's session lifetime. */
    @Test
    fun `the interactive session lifetime reaches the caller`() {
        serve(
            "/iar" to MockResponse().setResponseCode(200).setBody(
                """{"status":"ok","type":"openid4vp_presentation","auth_session":"sess-1",
                    "expires_in":120,"openid4vp_request":{"nonce":"n"}}"""
            )
        )

        val result = resolve(authConfig(interactive = server.url("/iar").toString()))

        assertEquals(AuthorizationOutcome.PRESENTATION_REQUIRED, result.outcome)
        assertEquals(120, result.expiresIn)
    }

    /**
     * `state` and `redirect_uri` are generated inside the SDK. Without them on the response nothing
     * can validate the browser callback, and the token request has to guess at a value it is
     * required to repeat verbatim (RFC 6749 section 4.1.3).
     */
    @Test
    fun `the response reports the state and redirect_uri that were actually sent`() {
        val result = resolve(authConfig())
        val request = result.request!!

        assertEquals(request.state, request.parameters["state"])
        assertEquals(request.redirectUri, request.parameters["redirect_uri"])
        assertEquals(request.nonce, request.parameters["nonce"])
        assertTrue(result.url!!.contains("state=${request.state}"))
    }

    /** Every outcome carries it, failures included -- that is when it is most needed. */
    @Test
    fun `a failure still reports what was sent`() {
        serve("/par" to MockResponse().setResponseCode(400).setBody("nope"))

        val result = resolve(authConfig(requirePar = true))

        assertEquals(AuthorizationOutcome.FAILED, result.outcome)
        assertEquals(AuthorizationTransportKind.PUSHED, result.request!!.transport)
        assertTrue(result.request!!.parameters.containsKey("code_challenge"))
    }
    // MARK: - The interaction type is the discriminator

    /**
     * `type` decides, not the shape of the payload: the wallet advertises
     * `interaction_types_supported` and the server answers by naming the one it chose. Reading the
     * payload instead would make that negotiation pointless.
     */
    @Test
    fun `an announced presentation with no request is refused rather than half-built`() {
        serve(
            "/iar" to MockResponse().setResponseCode(200).setBody(
                """{"status":"ok","type":"openid4vp_presentation","auth_session":"s1"}"""
            )
        )

        val result = resolve(authConfig(interactive = server.url("/iar").toString()))

        assertEquals(AuthorizationOutcome.FAILED, result.outcome)
        assertTrue(result.error!!.errorDescription!!.contains("no openid4vp_request"))
    }

    @Test
    fun `an announced redirect with no request_uri is refused`() {
        serve(
            "/iar" to MockResponse().setResponseCode(200)
                .setBody("""{"status":"ok","type":"redirect_to_web"}""")
        )

        val result = resolve(authConfig(interactive = server.url("/iar").toString()))

        assertEquals(AuthorizationOutcome.FAILED, result.outcome)
        assertTrue(result.error!!.errorDescription!!.contains("no request_uri"))
    }

    /** A payload the wallet could act on does not override a type it did not advertise. */
    @Test
    fun `an unadvertised interaction type is refused even when it carries a usable payload`() {
        serve(
            "/iar" to MockResponse().setResponseCode(200).setBody(
                """{"type":"something_new","request_uri":"urn:x","openid4vp_request":{"nonce":"n"}}"""
            )
        )

        val result = resolve(authConfig(interactive = server.url("/iar").toString()))

        assertEquals(AuthorizationOutcome.FAILED, result.outcome)
        assertTrue(result.error!!.errorDescription!!.contains("does not support: something_new"))
    }

    /** The presentation URL must not carry request_uri -- see the transport's KDoc. */
    @Test
    fun `the presentation url omits request_uri and keeps status`() {
        serve(
            "/iar" to MockResponse().setResponseCode(200).setBody(
                """{"status":"ok","type":"openid4vp_presentation","auth_session":"s1",
                    "request_uri":"urn:should-not-appear","openid4vp_request":{"nonce":"n"}}"""
            )
        )

        val result = resolve(authConfig(interactive = server.url("/iar").toString()))

        assertEquals(AuthorizationOutcome.PRESENTATION_REQUIRED, result.outcome)
        assertTrue(result.url!!.contains("status=ok"))
        assertTrue(result.url!!.contains("type=openid4vp_presentation"))
        assertTrue(result.url!!.contains("openid4vp_request="))
        assertTrue(!result.url!!.contains("request_uri="))
    }
}
