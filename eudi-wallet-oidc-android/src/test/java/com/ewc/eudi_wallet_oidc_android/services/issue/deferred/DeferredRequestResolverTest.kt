package com.ewc.eudi_wallet_oidc_android.services.issue.deferred

import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletAttestation
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.CredentialOutcome
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The deferred credential request, section 9.
 *
 * None of these could have passed before: both deferred functions ran through `SafeApiCall` and
 * turned every failure into a `null` and a `println`, so `issuance_pending` -- the credential is
 * still coming -- was indistinguishable from `invalid_transaction_id`, the transaction is dead.
 */
class DeferredRequestResolverTest {

    private lateinit var server: MockWebServer

    @Before fun setUp() { server = MockWebServer(); server.start() }
    @After fun tearDown() { server.shutdown() }

    private fun session() = IssuanceSession(
        credentialOffer = CredentialOffer(credentialIssuer = "https://issuer.example.com"),
        issuerConfig = IssuerWellKnownConfiguration(
            credentialIssuer = "https://issuer.example.com",
            deferredCredentialEndpoint = server.url("/deferred").toString(),
        ),
        authConfig = null,
    )

    private fun resolve(
        transaction: DeferredTransaction = DeferredTransaction.TransactionId("txn-1"),
        withDpop: Boolean = false,
        policy: DeferredRequestPolicy = DeferredRequestPolicy.Default,
    ) = runBlocking {
        DeferredRequestResolver(policy).resolve(
            session = session(),
            token = TokenResponse(accessToken = "at-1"),
            transaction = transaction,
            attestation = if (withDpop) {
                WalletAttestation(null, null, ECKeyGenerator(Curve.P_256).keyID("d").generate())
            } else null,
        )
    }

    // MARK: - the request

    @Test
    fun `the transaction id is sent in the body`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"credential":"vc-1"}"""))

        resolve()

        val body = JSONObject(server.takeRequest().body.readUtf8())
        assertEquals("txn-1", body.getString("transaction_id"))
    }

    @Test
    fun `a credential identifier is sent alongside it when there is one`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"credential":"vc-1"}"""))

        resolve(DeferredTransaction.TransactionId("txn-1", credentialIdentifier = "cred-a"))

        val body = JSONObject(server.takeRequest().body.readUtf8())
        assertEquals("cred-a", body.getString("credential_identifier"))
    }

    @Test
    fun `the policy can withhold the credential identifier`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"credential":"vc-1"}"""))

        resolve(
            DeferredTransaction.TransactionId("txn-1", credentialIdentifier = "cred-a"),
            policy = DeferredRequestPolicy.Legacy,
        )

        val body = JSONObject(server.takeRequest().body.readUtf8())
        assertTrue(body.isNull("credential_identifier") || !body.has("credential_identifier"))
    }

    /**
     * The draft form carries its handle as the bearer token and sends nothing. The whole reason
     * there used to be two functions and a stored version integer choosing between them.
     */
    @Test
    fun `the draft acceptance token authenticates with the handle and sends an empty body`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"credential":"vc-1"}"""))

        resolve(DeferredTransaction.LegacyAcceptanceToken("acc-1"))

        val request = server.takeRequest()
        assertEquals("Bearer acc-1", request.getHeader("Authorization"))
        assertEquals(0, JSONObject(request.body.readUtf8()).length())
    }

    @Test
    fun `a DPoP bound token stays DPoP bound on the deferred endpoint`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"credential":"vc-1"}"""))

        resolve(withDpop = true)

        val request = server.takeRequest()
        assertEquals("DPoP at-1", request.getHeader("Authorization"))
        assertTrue(request.getHeader("DPoP")?.isNotBlank() == true)
    }

    // MARK: - reading the answer

    @Test
    fun `a credential ends the polling`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"credentials":[{"credential":"vc-1"},{"credential":"vc-2"}]}"""))

        val outcome = resolve()

        assertTrue(outcome is CredentialOutcome.Issued)
        assertEquals(listOf("vc-1", "vc-2"), (outcome as CredentialOutcome.Issued).credentials)
    }

    /**
     * Section 9.3. This is the whole point of the pass: still-pending is not a failure, and the
     * issuer's own `interval` replaces the fixed one the wallet used to guess.
     */
    @Test
    fun `issuance_pending comes back as Deferred with the issuer's interval`() {
        server.enqueue(
            MockResponse().setResponseCode(400)
                .setBody("""{"error":"issuance_pending","interval":42}""")
        )

        val outcome = resolve()

        assertTrue("expected Deferred, got $outcome", outcome is CredentialOutcome.Deferred)
        outcome as CredentialOutcome.Deferred
        assertEquals("txn-1", outcome.transactionId)
        assertEquals(42, outcome.interval)
    }

    @Test
    fun `issuance_pending without an interval still defers`() {
        server.enqueue(MockResponse().setResponseCode(400).setBody("""{"error":"issuance_pending"}"""))

        val outcome = resolve()

        assertTrue(outcome is CredentialOutcome.Deferred)
        assertNull((outcome as CredentialOutcome.Deferred).interval)
    }

    /** A dead transaction must stop the polling, which a null could never say. */
    @Test
    fun `invalid_transaction_id is a failure carrying the code and the status`() {
        server.enqueue(
            MockResponse().setResponseCode(400)
                .setBody("""{"error":"invalid_transaction_id","error_description":"expired"}""")
        )

        val outcome = resolve()

        assertTrue(outcome is CredentialOutcome.Failed)
        val error = (outcome as CredentialOutcome.Failed).error
        assertEquals("invalid_transaction_id", error.errorCode)
        assertEquals(400, error.httpStatus)
        assertEquals("expired", error.errorDescription)
    }

    /** Section 9.2: the deferred response may itself be deferred again. */
    @Test
    fun `a response that defers again yields the new handle`() {
        server.enqueue(
            MockResponse().setResponseCode(200)
                .setBody("""{"transaction_id":"txn-2","interval":5}""")
        )

        val outcome = resolve()

        assertTrue(outcome is CredentialOutcome.Deferred)
        assertEquals("txn-2", (outcome as CredentialOutcome.Deferred).transactionId)
        assertEquals(5, outcome.interval)
    }

    /**
     * Some issuers answer a still-pending poll with 200 and an `interval`, naming no transaction id
     * at all, rather than section 9.3's 400 + `issuance_pending`. Read strictly that is "neither a
     * credential nor a transaction id" and the polling stops; the handle we are already polling
     * with is the one the issuer still means, so it is reused.
     */
    @Test
    fun `a 200 carrying only an interval keeps polling with the handle we already hold`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"interval":7}"""))

        val outcome = resolve()

        assertTrue("expected Deferred, got $outcome", outcome is CredentialOutcome.Deferred)
        outcome as CredentialOutcome.Deferred
        assertEquals("txn-1", outcome.transactionId)
        assertEquals(7, outcome.interval)
    }

    /** The interval is what distinguishes "come back later" from a malformed body. Without it the
     * response really is unreadable, and saying so beats polling something that will never arrive. */
    @Test
    fun `a 200 with no interval and no ids is still a failure`() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{}"""))

        val outcome = resolve()

        assertTrue(outcome is CredentialOutcome.Failed)
        assertTrue(
            (outcome as CredentialOutcome.Failed).error.errorDescription
                ?.contains("neither a credential nor a transaction id") == true
        )
    }

    @Test
    fun `a DPoP nonce challenge is answered once`() {
        server.enqueue(
            MockResponse().setResponseCode(400)
                .setHeader("DPoP-Nonce", "dpop-1")
                .setBody("""{"error":"use_dpop_nonce"}""")
        )
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"credential":"vc-1"}"""))

        val outcome = resolve(withDpop = true)

        assertEquals(2, server.requestCount)
        assertTrue(outcome is CredentialOutcome.Issued)
    }

    @Test
    fun `an issuer with no deferred endpoint is a named failure`() {
        val outcome = runBlocking {
            DeferredRequestResolver().resolve(
                session = IssuanceSession(
                    credentialOffer = null,
                    issuerConfig = IssuerWellKnownConfiguration(credentialIssuer = "https://issuer.example.com"),
                    authConfig = null,
                ),
                token = TokenResponse(accessToken = "at-1"),
                transaction = DeferredTransaction.TransactionId("txn-1"),
            )
        }

        assertTrue(outcome is CredentialOutcome.Failed)
        assertTrue(
            (outcome as CredentialOutcome.Failed).error.errorDescription
                ?.contains("deferred credential endpoint") == true
        )
    }
}
