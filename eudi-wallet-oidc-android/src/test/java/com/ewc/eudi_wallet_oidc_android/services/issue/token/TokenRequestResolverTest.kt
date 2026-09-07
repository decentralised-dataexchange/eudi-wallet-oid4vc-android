package com.ewc.eudi_wallet_oidc_android.services.issue.token

import com.ewc.eudi_wallet_oidc_android.models.AuthorisationServerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.Grants
import com.ewc.eudi_wallet_oidc_android.models.PreAuthorizationCode
import com.ewc.eudi_wallet_oidc_android.models.TxCode
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletAttestation
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
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
 * The token request end to end, against a mock server.
 *
 * Several of these could not have passed before: `SafeApiCall` turned every 4xx into a failure
 * carrying the body as a bare string, discarding the status code and every header -- so the OAuth
 * error code, the HTTP status and the `DPoP-Nonce` header were all unreachable.
 */
class TokenRequestResolverTest {

    private lateinit var server: MockWebServer

    @Before fun setUp() { server = MockWebServer(); server.start() }
    @After fun tearDown() { server.shutdown() }

    private fun session(txCode: TxCode? = null) = IssuanceSession(
        credentialOffer = CredentialOffer(
            credentialIssuer = "https://issuer.example.com",
            version = 2,
            grants = Grants(
                preAuthorizationCode = PreAuthorizationCode(
                    preAuthorizedCode = "pre-1",
                    transactionCode = txCode,
                )
            ),
        ),
        issuerConfig = null,
        authConfig = AuthorisationServerWellKnownConfiguration(
            tokenEndpoint = server.url("/token").toString(),
        ),
    )

    private fun resolve(
        grant: TokenGrant = TokenGrant.PreAuthorized("pre-1"),
        session: IssuanceSession = session(),
        withDpop: Boolean = false,
    ) = runBlocking {
        TokenRequestResolver().resolve(
            session = session,
            wallet = WalletIdentity("did:key:zabc", null),
            attestation = if (withDpop) {
                WalletAttestation(
                    attestationJwt = null,
                    proofOfPossession = null,
                    dpopKey = ECKeyGenerator(Curve.P_256).keyID("k").generate(),
                )
            } else null,
            grant = grant,
        )
    }

    @Test
    fun `an access token is returned and the body is form encoded`() {
        server.enqueue(
            MockResponse().setResponseCode(200)
                .setBody("""{"access_token":"at-1","token_type":"bearer","expires_in":300}""")
        )

        val result = resolve()

        assertEquals("at-1", result.tokenResponse?.accessToken)
        assertNull(result.errorResponse)
        val body = server.takeRequest().body.readUtf8()
        assertTrue(body.contains("grant_type=urn"))
        assertTrue(body.contains("pre-authorized_code=pre-1"))
    }

    /** The status and the OAuth code both used to be lost before the caller saw them. */
    @Test
    fun `a rejection reports the oauth code, the description and the status`() {
        server.enqueue(
            MockResponse().setResponseCode(400).setBody(
                """{"error":"invalid_grant","error_description":"PIN is wrong"}"""
            )
        )

        val result = resolve()

        assertEquals("invalid_grant", result.errorResponse?.errorCode)
        assertEquals("PIN is wrong", result.errorResponse?.errorDescription)
        assertEquals(400, result.errorResponse?.httpStatus)
        assertNull(result.tokenResponse?.accessToken)
    }

    /** RFC 9449 section 8: 400 + use_dpop_nonce + a DPoP-Nonce header. Exactly once. */
    @Test
    fun `a dpop nonce challenge is retried once with the nonce`() {
        server.enqueue(
            MockResponse().setResponseCode(400)
                .setHeader("DPoP-Nonce", "nonce-1")
                .setBody("""{"error":"use_dpop_nonce"}""")
        )
        server.enqueue(
            MockResponse().setResponseCode(200).setBody("""{"access_token":"at-2"}""")
        )

        val result = resolve(withDpop = true)

        assertEquals("at-2", result.tokenResponse?.accessToken)
        assertEquals(2, server.requestCount)

        // The point of the retry is the nonce claim, not merely that a second request happened:
        // the first proof carries none, the second carries the one the server supplied.
        assertNull(nonceClaimOf(server.takeRequest().getHeader("DPoP")))
        assertEquals("nonce-1", nonceClaimOf(server.takeRequest().getHeader("DPoP")))
    }

    /** The `nonce` claim of a DPoP proof, or null when it carries none. */
    private fun nonceClaimOf(proof: String?): String? {
        val payload = proof?.split(".")?.getOrNull(1) ?: return null
        val json = String(java.util.Base64.getUrlDecoder().decode(payload))
        return org.json.JSONObject(json).let { if (it.has("nonce")) it.getString("nonce") else null }
    }

    @Test
    fun `a second nonce challenge gives up rather than looping`() {
        repeat(2) {
            server.enqueue(
                MockResponse().setResponseCode(400)
                    .setHeader("DPoP-Nonce", "nonce-$it")
                    .setBody("""{"error":"use_dpop_nonce"}""")
            )
        }

        val result = resolve(withDpop = true)

        assertEquals(2, server.requestCount)
        assertEquals("use_dpop_nonce", result.errorResponse?.errorCode)
    }

    /** RFC 9449 section 8.2: a nonce can rotate on a success, and must be used from then on. */
    @Test
    fun `a nonce supplied on a success is carried back to the caller`() {
        server.enqueue(
            MockResponse().setResponseCode(200)
                .setHeader("DPoP-Nonce", "nonce-next")
                .setBody("""{"access_token":"at-3"}""")
        )

        assertEquals("nonce-next", resolve(withDpop = true).dpopNonce)
    }

    /**
     * Section 6.1 obliges the wallet to send a Transaction Code when the offer carried the object,
     * even an empty one. Failing here says something the user can act on, rather than spending the
     * one-time code on a request that cannot succeed.
     */
    @Test
    fun `a missing transaction code fails before the request is made`() {
        val result = resolve(session = session(txCode = TxCode()))

        assertEquals(0, server.requestCount)
        assertTrue(result.errorResponse?.errorDescription!!.contains("transaction code"))
    }

    /** Used to be a bare null with no log: SafeApiCall passed 3xx through as success. */
    @Test
    fun `an unexpected status is a failure with a reason`() {
        server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", "https://elsewhere"))

        val result = resolve()

        assertNotNull(result.errorResponse)
        assertEquals(302, result.errorResponse?.httpStatus)
    }
}
