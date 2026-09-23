package com.ewc.eudi_wallet_oidc_android.services.issue.credential

import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletAttestation
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.SignedJWT
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

/**
 * The credential request end to end.
 *
 * Several of these could not have passed before: `SafeApiCall` turned every 4xx into a failure
 * carrying the body as a bare string, so the issuer's `error` code, the HTTP status and any
 * `DPoP-Nonce` header were gone before the caller saw them.
 */
class CredentialRequestResolverTest {

    private lateinit var server: MockWebServer

    @Before fun setUp() { server = MockWebServer(); server.start() }
    @After fun tearDown() { server.shutdown() }

    private fun session(nonceEndpoint: String? = null) = IssuanceSession(
        credentialOffer = CredentialOffer(credentialIssuer = "https://issuer.example.com"),
        issuerConfig = IssuerWellKnownConfiguration(
            credentialIssuer = "https://issuer.example.com",
            credentialEndpoint = server.url("/credential").toString(),
            nonceEndpoint = nonceEndpoint,
        ),
        authConfig = null,
    )

    private fun resolve(
        session: IssuanceSession = session(),
        token: TokenResponse = TokenResponse(accessToken = "at-1", cNonce = "nonce-1"),
        withDpop: Boolean = false,
        policy: CredentialRequestPolicy = CredentialRequestPolicy.Default,
    ) = runBlocking {
        CredentialRequestResolver(policy).resolve(
            session = session,
            wallet = WalletIdentity("did:key:zabc", ECKeyGenerator(Curve.P_256).keyID("k").generate()),
            token = token,
            subject = CredentialSubject.ByConfiguration("PidSdJwt"),
            issuer = "did:key:zabc",
            attestation = if (withDpop) {
                WalletAttestation(null, null, ECKeyGenerator(Curve.P_256).keyID("d").generate())
            } else null,
        )
    }

    /**
     * The deferred leg reuses the handle it is polling with when an issuer defers without naming
     * one. The credential leg must not: this is the *first* request, so there is no prior handle,
     * and inventing one would start polling something that was never allocated.
     */
    @Test
    fun `a 200 carrying only an interval is a failure on the credential leg`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"interval":7}"""))

        val outcome = resolve()

        assertTrue("expected Failed, got $outcome", outcome is CredentialOutcome.Failed)
    }

    @Test
    fun `a credential is returned`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"credential":"vc-1"}"""))

        val outcome = resolve()

        assertTrue(outcome is CredentialOutcome.Issued)
        assertEquals(listOf("vc-1"), (outcome as CredentialOutcome.Issued).credentials)
    }

    /**
     * Section 8.3's `credentials` is an array. The previous implementation read index 0 and dropped
     * the rest -- at six call sites in the wallet.
     */
    @Test
    fun `every credential in a plural response is returned, not just the first`() {
        server.enqueue(
            MockResponse().setResponseCode(200).setBody(
                """{"credentials":[{"credential":"vc-1"},{"credential":"vc-2"}],"notification_id":"n-1","c_nonce":"next"}"""
            )
        )

        val outcome = resolve() as CredentialOutcome.Issued

        assertEquals(listOf("vc-1", "vc-2"), outcome.credentials)
        assertEquals("n-1", outcome.notificationId)
        // Section 8.3: the issuer SHOULD return a fresh nonce; it was not modelled at all before.
        assertEquals("next", outcome.cNonce)
    }

    /** Deferral is an outcome, not a flag the caller infers from a non-null token. */
    @Test
    fun `a transaction id is a deferred outcome`() {
        server.enqueue(
            MockResponse().setResponseCode(200).setBody("""{"transaction_id":"tx-1","interval":10}""")
        )

        val outcome = resolve()

        assertTrue(outcome is CredentialOutcome.Deferred)
        assertEquals("tx-1", (outcome as CredentialOutcome.Deferred).transactionId)
        assertEquals(10, outcome.interval)
    }

    /** Draft issuers call the same handle `acceptance_token`. */
    @Test
    fun `an acceptance token is the same deferred outcome`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"acceptance_token":"acc-1"}"""))

        assertEquals("acc-1", (resolve() as CredentialOutcome.Deferred).transactionId)
    }

    @Test
    fun `a rejection reports the issuer's own error code and the status`() {
        server.enqueue(
            MockResponse().setResponseCode(400)
                .setBody("""{"error":"invalid_proof","error_description":"nonce is stale"}""")
        )

        val outcome = resolve() as CredentialOutcome.Failed

        assertEquals("invalid_proof", outcome.error.errorCode)
        assertEquals("nonce is stale", outcome.error.errorDescription)
        assertEquals(400, outcome.error.httpStatus)
    }

    /**
     * Section 8.3.1: "The Credential Issuer MAY return a new `c_nonce` value in an error response".
     * Neither platform ever took one up on it.
     */
    @Test
    fun `a rejected proof is re-signed once with the fresh nonce`() {
        server.enqueue(
            MockResponse().setResponseCode(400)
                .setBody("""{"error":"invalid_proof","c_nonce":"nonce-2"}""")
        )
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"credential":"vc-1"}"""))

        val outcome = resolve()

        assertTrue(outcome is CredentialOutcome.Issued)
        assertEquals(2, server.requestCount)
        assertEquals("nonce-1", nonceOfProofIn(server.takeRequest().body.readUtf8()))
        assertEquals("nonce-2", nonceOfProofIn(server.takeRequest().body.readUtf8()))
    }

    @Test
    fun `a second rejection gives up rather than looping`() {
        repeat(2) {
            server.enqueue(
                MockResponse().setResponseCode(400)
                    .setBody("""{"error":"invalid_proof","c_nonce":"nonce-$it"}""")
            )
        }

        val outcome = resolve()

        assertEquals(2, server.requestCount)
        assertEquals("invalid_proof", (outcome as CredentialOutcome.Failed).error.errorCode)
    }

    /** RFC 9449 section 8, which the credential endpoint has never handled. */
    @Test
    fun `a dpop nonce challenge is retried once`() {
        server.enqueue(
            MockResponse().setResponseCode(400)
                .setHeader("DPoP-Nonce", "dnonce-1")
                .setBody("""{"error":"use_dpop_nonce"}""")
        )
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"credential":"vc-1"}"""))

        val outcome = resolve(withDpop = true)

        assertTrue("got $outcome", outcome is CredentialOutcome.Issued)
        assertEquals(2, server.requestCount)
    }

    /**
     * Section 8.2 makes `nonce` REQUIRED in the proof when the issuer publishes a Nonce Endpoint.
     * It used to be omitted silently, producing `invalid_proof` a round trip later.
     */
    @Test
    fun `a missing nonce against a nonce-endpoint issuer fails before the request`() {
        // The endpoint answers, but with nothing usable -- so the proof has no nonce to carry.
        server.enqueue(MockResponse().setResponseCode(404))
        val outcome = resolve(
            session = session(nonceEndpoint = server.url("/nonce").toString()),
            token = TokenResponse(accessToken = "at-1", cNonce = null),
        )

        assertTrue(outcome is CredentialOutcome.Failed)
        assertTrue((outcome as CredentialOutcome.Failed).error.errorDescription!!.contains("c_nonce"))
    }

    @Test
    fun `an empty body is a failure with a reason, not a silent success`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody(""))

        val outcome = resolve()

        assertNotNull((outcome as CredentialOutcome.Failed).error.errorDescription)
    }

    /** The proof the request actually carried. */
    private fun nonceOfProofIn(body: String): String? {
        val proof = Regex(""""jwt"\s*:\s*"([^"]+)"""").find(body)?.groupValues?.get(1)
            ?: Regex(""""jwt"\s*:\s*\["([^"]+)"]""").find(body)?.groupValues?.get(1)
            ?: return null
        return SignedJWT.parse(proof).jwtClaimsSet.getStringClaim("nonce")
    }
}
