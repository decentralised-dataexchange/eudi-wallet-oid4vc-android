package com.ewc.eudi_wallet_oidc_android.services.issue.authorization

import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * How the in-app transport reads the redirect the authorization server sends.
 *
 * The cases and the order they are tested in are the previous implementation's, because deployed
 * servers are distinguished only by which one matches. Each is asserted here so the ordering cannot
 * drift unnoticed.
 */
class InAppAuthorizationTest {

    private lateinit var server: MockWebServer

    @Before fun setUp() { server = MockWebServer(); server.start() }
    @After fun tearDown() { server.shutdown() }

    private fun redirect(location: String) {
        server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", location))
    }

    private fun resolve() = runBlocking {
        AuthorizationRequestResolver().resolve(
            session = IssuanceSession(
                credentialOffer = CredentialOffer(credentialIssuer = "https://issuer.example.com"),
                issuerConfig = null,
                authConfig = AuthorisationServerWellKnownConfiguration(
                    authorizationEndpoint = server.url("/authorize").toString(),
                ),
            ),
            wallet = WalletIdentity("did:key:zabc", null),
            attestation = null,
            codeVerifier = "a".repeat(64),
            authorizationDetails = "[]",
            scopeTypes = listOf("PidSdJwt"),
            selection = CredentialSelection(format = "jwt_vc_json"),
            mode = AuthorizationMode.InApp,
        )
    }

    @Test
    fun `a redirect carrying a code becomes AuthorizationCode`() {
        redirect("openid://callback?code=abc123&state=xyz")

        val result = resolve()

        assertEquals(AuthorizationOutcome.AUTHORIZATION_CODE, result.outcome)
        assertEquals("abc123", result.code)
        assertEquals("xyz", result.state)
        // the state that was sent, so the caller can compare the two
        assertNotNull(result.request!!.state)
    }

    /** The reason is now named, and the redirect is still carried for the deprecated entry point. */
    @Test
    fun `a redirect carrying an error becomes Failed with the description`() {
        redirect("openid://callback?error=access_denied&error_description=User%20said%20no")

        val result = resolve()

        assertEquals(AuthorizationOutcome.FAILED, result.outcome)
        assertEquals("access_denied", result.error!!.errorCode)
        assertEquals("User said no", result.error!!.errorDescription)
        assertTrue(result.location!!.contains("error=access_denied"))
    }

    @Test
    fun `a presentation definition becomes PresentationRequired`() {
        redirect("openid://callback?presentation_definition=%7B%7D")
        assertEquals(AuthorizationOutcome.PRESENTATION_REQUIRED, resolve().outcome)
    }

    /** A bare request_uri -- no response_type, no state -- is a presentation, not an authorization. */
    @Test
    fun `a bare request_uri becomes PresentationRequired`() {
        redirect("openid://callback?request_uri=https%3A%2F%2Fverifier.example.com%2Freq")
        assertEquals(AuthorizationOutcome.PRESENTATION_REQUIRED, resolve().outcome)

        // With response_type and state it is an ordinary authorization redirect, not a presentation.
        redirect("https://as.example.com/next?request_uri=x&response_type=code&state=1")
        assertEquals(AuthorizationOutcome.OPEN_IN_BROWSER, resolve().outcome)
    }

    @Test
    fun `a redirect away from our own redirect_uri is somewhere the user has to go`() {
        redirect("https://bankid.example.com/start?session=1")

        val result = resolve()

        assertEquals(AuthorizationOutcome.OPEN_IN_BROWSER, result.outcome)
        assertTrue(result.url!!.startsWith("https://bankid"))
    }

    /** Used to be a bare `return null` the caller could not tell from anything else. */
    @Test
    fun `no redirect at all reports a reason`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("<html/>"))

        val result = resolve()

        assertEquals(AuthorizationOutcome.FAILED, result.outcome)
        assertTrue(result.error!!.errorDescription!!.contains("no redirect"))
    }

    /**
     * A 502 used to throw a bare `Exception` -- not an AuthorizationException, so it escaped the
     * resolver's catch and reached the app as a thrown exception instead of an outcome. The message
     * is unchanged; only the way it arrives is.
     */
    @Test
    fun `a 502 is reported as a failure rather than thrown`() {
        server.enqueue(MockResponse().setResponseCode(502))

        val result = resolve()

        assertEquals(AuthorizationOutcome.FAILED, result.outcome)
        assertTrue(result.error!!.errorDescription!!.contains("Unexpected error"))
        assertEquals(502, result.error!!.httpStatus)
    }
    /**
     * A 4xx used to fall through to "gave no redirect to continue with", which threw the body and
     * the OAuth code away -- the same loss already fixed for the PAR and interactive transports.
     */
    @Test
    fun `a rejection reports the server's own error rather than a missing redirect`() {
        server.enqueue(
            MockResponse().setResponseCode(400).setBody(
                """{"error":"invalid_request","error_description":"redirect_uri is not registered"}"""
            )
        )

        val result = resolve()

        assertEquals(AuthorizationOutcome.FAILED, result.outcome)
        assertEquals("invalid_request", result.error!!.errorCode)
        assertEquals("redirect_uri is not registered", result.error!!.errorDescription)
        assertEquals(400, result.error!!.httpStatus)
    }

    /** The interactive transport carried it; this one dropped it on the floor. */
    @Test
    fun `a presentation redirect carries its auth_session`() {
        redirect("openid://callback?presentation_definition=%7B%7D&auth_session=sess-9")

        val result = resolve()

        assertEquals(AuthorizationOutcome.PRESENTATION_REQUIRED, result.outcome)
        assertEquals("sess-9", result.authSession)
    }
}
