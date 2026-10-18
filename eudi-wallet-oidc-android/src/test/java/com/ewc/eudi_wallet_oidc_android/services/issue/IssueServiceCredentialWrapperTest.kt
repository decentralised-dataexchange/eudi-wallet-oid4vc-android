package com.ewc.eudi_wallet_oidc_android.services.issue

import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.Credentials
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The deprecated fourteen-parameter `processCredentialRequest` is a wrapper over
 * `requestCredential`, so a host still on it sends the same body as the new API.
 *
 * Before this it kept its own copy of the leg, which named the credential by the nonce endpoint
 * and chose the proof form by a `credential_metadata` lookup, so the fixes to the new path never
 * reached it.
 */
class IssueServiceCredentialWrapperTest {

    private lateinit var server: MockWebServer

    @Before fun setUp() { server = MockWebServer(); server.start() }
    @After fun tearDown() { server.shutdown() }

    private val offer = CredentialOffer(
        credentialIssuer = "https://issuer.example.com",
        credentials = arrayListOf(Credentials(types = arrayListOf("PidSdJwt"))),
        version = 2,
    )

    private fun issuerConfig() = IssuerWellKnownConfiguration(
        credentialIssuer = "https://issuer.example.com",
        credentialEndpoint = server.url("/credential").toString(),
        credentialsSupported = mapOf("PidSdJwt" to mapOf("format" to "dc+sd-jwt")),
        version = 2,
    )

    @Suppress("DEPRECATION")
    private fun request(
        token: TokenResponse = TokenResponse(accessToken = "at-1"),
        offer: CredentialOffer = this.offer,
        issuerConfig: IssuerWellKnownConfiguration = issuerConfig(),
    ) = runBlocking {
        IssueService().processCredentialRequest(
            did = "did:key:zabc",
            subJwk = ECKeyGenerator(Curve.P_256).keyID("k").generate(),
            nonce = "nonce-1",
            credentialOffer = offer,
            issuerConfig = issuerConfig,
            accessToken = token,
            authorizationDetail = null,
            index = 0,
            ecKeyWithAlgEnc = null,
            credentialRequestEncryptionInfo = null,
            authConfig = null,
            dpopKey = null,
            attachKeyAttestation = false,
            keyAttestationJwt = null,
            clientId = "did:key:zabc",
            additionalProofKeys = null,
        )
    }

    /** A 1.0 issuer gets the 1.0 body through the old entry point too. */
    @Test
    fun `the deprecated entry point sends the 1_0 body`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"credentials":[{"credential":"vc-1"}]}"""))

        val result = request()

        val body = JSONObject(server.takeRequest().body.readUtf8())
        assertEquals("PidSdJwt", body.getString("credential_configuration_id"))
        assertTrue(body.has("proofs"))
        assertFalse(body.has("proof"))
        assertFalse(body.has("format"))
        assertEquals("vc-1", result?.credentialResponse?.credentials?.firstOrNull()?.credential)
    }

    /** The issuer's error reaches the caller as an errorResponse, not a bare null. */
    @Test
    fun `a rejection is reported with the issuer's code`() {
        server.enqueue(MockResponse().setResponseCode(400).setBody("""{"error":"invalid_proof","error_description":"stale"}"""))

        val result = request()

        assertNotNull(result?.errorResponse)
        assertEquals("invalid_proof", result?.errorResponse?.errorCode)
    }

    /**
     * A deferral comes back as a transaction id the caller can poll with, and nothing else:
     * hosts pick the deferred polling call by `acceptanceToken != null`, so filling it for a 1.0
     * issuer made them poll with the draft call until the transaction expired.
     */
    @Test
    fun `a deferral is reported as a transaction id`() {
        server.enqueue(MockResponse().setResponseCode(202).setBody("""{"transaction_id":"tx-1","interval":5}"""))

        val result = request()

        assertEquals("tx-1", result?.credentialResponse?.transactionId)
        assertEquals(5, result?.credentialResponse?.interval)
        assertNull(result?.credentialResponse?.acceptanceToken)
    }

    /** A draft issuer's deferral keeps the acceptance token, which is what its polling call sends. */
    @Test
    fun `a draft deferral is reported as an acceptance token`() {
        server.enqueue(MockResponse().setResponseCode(202).setBody("""{"acceptance_token":"accept-1"}"""))

        val result = request(
            offer = offer.copy(version = 1),
            issuerConfig = issuerConfig().copy(credentialsSupported = listOf(mapOf("format" to "jwt_vc")), version = 1),
        )

        assertEquals("accept-1", result?.credentialResponse?.acceptanceToken)
        assertEquals("accept-1", result?.credentialResponse?.transactionId)
    }
}
