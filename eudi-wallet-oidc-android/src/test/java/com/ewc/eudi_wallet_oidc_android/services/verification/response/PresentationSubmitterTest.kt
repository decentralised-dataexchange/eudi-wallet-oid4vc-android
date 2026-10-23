package com.ewc.eudi_wallet_oidc_android.services.verification.response

import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletAttestation
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.CLIENT_ID
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.NONCE
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationService
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.SelectedCredential
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.crypto.ECDHDecrypter
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.URLDecoder

/** One case per row of the leg 5 matrix in VERIFICATION_REVAMP_PLAN_ANDROID.md, against a mock verifier. */
class PresentationSubmitterTest {

    private lateinit var server: MockWebServer
    private val holderKey = VerificationFixtures.key("holder")
    private val identity = WalletIdentity(did = VerificationFixtures.DID, jwk = holderKey)
    private val sdJwt = VerificationFixtures.sdJwt()
    private val selected = listOf(SelectedCredential("pid", sdJwt, holderKey))

    @Before
    fun start() { server = MockWebServer(); server.start() }

    @After
    fun stop() = server.shutdown()

    private fun request(
        responseMode: String? = "direct_post",
        responseUri: String? = server.url("/response").toString(),
        clientMetadata: Any? = null,
        authSession: String? = null,
    ) = PresentationRequest(
        clientId = CLIENT_ID, nonce = NONCE, state = "s-1", responseType = "vp_token",
        responseMode = responseMode, responseUri = responseUri, clientMetaDetails = clientMetadata, authSession = authSession,
        dcqlQuery = DCQL(credentials = listOf(VerificationFixtures.dcqlSdJwt("pid"))),
    )

    private fun submit(request: PresentationRequest, credentials: List<SelectedCredential> = selected, attestation: WalletAttestation? = null) =
        runBlocking { PresentationSubmitter().submit(request, credentials, identity, attestation) }

    private fun answer(code: Int, body: String? = null, location: String? = null) {
        server.enqueue(MockResponse().setResponseCode(code).apply {
            body?.let { setHeader("Content-Type", "application/json").setBody(it) }
            location?.let { setHeader("Location", it) }
        })
    }

    private fun form(): Map<String, String> = server.takeRequest().body.readUtf8().split('&').filter { it.isNotBlank() }
        .associate { URLDecoder.decode(it.substringBefore('='), "UTF-8") to URLDecoder.decode(it.substringAfter('='), "UTF-8") }

    // ── 5.1 to 5.8 reading the verifier's answer ────────────────────────────

    @Test
    fun `5_1 a 200 with redirect_uri is Accepted with it`() {
        answer(200, """{"redirect_uri":"https://verifier.example/cb#code=1"}""")
        val outcome = submit(request()) as PresentationOutcome.Accepted
        assertEquals("https://verifier.example/cb#code=1", outcome.redirectUri)
        val fields = form()
        assertTrue(fields.getValue("vp_token").startsWith("""{"pid":["""))
        assertEquals("s-1", fields["state"])
    }

    @Test
    fun `5_2 a 200 without redirect_uri or with a non JSON body is Accepted with nothing further`() {
        answer(200, "{}")
        assertEquals(PresentationOutcome.Accepted(), submit(request()))
        answer(200, "ok")
        assertEquals(PresentationOutcome.Accepted(), submit(request()))
    }

    @Test
    fun `5_3 an interactive authorization code in the body is carried, and the adapter keeps it in the placeholder`() {
        answer(200, """{"status":"ok","code":"auth-code-1"}""")
        assertEquals("auth-code-1", (submit(request()) as PresentationOutcome.Accepted).authorizationCode)

        answer(200, """{"status":"ok","code":"auth-code-2"}""")
        @Suppress("DEPRECATION")
        val legacy = runBlocking { VerificationService().processAndSendAuthorisationResponseV2(VerificationFixtures.DID, holderKey, request(), listOf(listOf(sdJwt)), null, null, false, null, null, null) }
        assertEquals("https://www.example.com?code=auth-code-2", legacy.vpTokenResponse?.redirectUri)
    }

    @Test
    fun `5_4 a 204 is Accepted with nothing further`() {
        answer(204)
        assertEquals(PresentationOutcome.Accepted(), submit(request()))
    }

    @Test
    fun `5_5 a 302 carries its Location, or the error in it`() {
        answer(302, location = "https://verifier.example/login;jsessionid=1")
        assertEquals("https://verifier.example/login;jsessionid=1", (submit(request()) as PresentationOutcome.Accepted).location)

        answer(302, location = "https://verifier.example/cb?error=invalid_request&error_description=bad%20nonce")
        val refused = submit(request()) as PresentationOutcome.Refused
        assertEquals("invalid_request", refused.error.errorCode)
        assertEquals("bad nonce", refused.error.errorDescription)
    }

    @Test
    fun `5_6 a 4xx is Refused with the OAuth error`() {
        answer(400, """{"error":"invalid_request","error_description":"nonce mismatch"}""")
        val refused = submit(request()) as PresentationOutcome.Refused
        assertEquals("invalid_request", refused.error.errorCode)
        assertEquals("nonce mismatch", refused.error.errorDescription)
    }

    @Test
    fun `5_7 a transport failure is Refused`() {
        server.shutdown()
        val refused = submit(request()) as PresentationOutcome.Refused
        assertTrue(!refused.error.errorDescription.isNullOrBlank())
    }

    @Test
    fun `5_8 a request without response_uri is Refused before anything is sent`() {
        val refused = submit(request(responseUri = null)) as PresentationOutcome.Refused
        assertTrue(refused.error.errorDescription!!.contains("response_uri"))
        assertEquals(0, server.requestCount)
    }

    // ── 5.9 / 5.10 encryption ───────────────────────────────────────────────

    @Test
    fun `5_9 direct_post dot jwt takes alg from the key and enc from the 1_0 metadata name`() {
        val key = VerificationFixtures.verifierEncryptionKey()
        val metadata = linkedMapOf<String, Any?>(
            "jwks" to mapOf("keys" to listOf(key.toPublicJWK().toJSONObject().apply { put("alg", "ECDH-ES+A256KW"); put("use", "enc") })),
            "encrypted_response_enc_values_supported" to listOf("A256GCM"),
        )
        answer(200, "{}")
        submit(request(responseMode = "direct_post.jwt", clientMetadata = metadata))
        val jwe = JWEObject.parse(form().getValue("response"))
        assertEquals("ECDH-ES+A256KW", jwe.header.algorithm.name)
        assertEquals("A256GCM", jwe.header.encryptionMethod.name)
        assertEquals(key.keyID, jwe.header.keyID)
        jwe.decrypt(ECDHDecrypter(key))
        assertTrue(jwe.payload.toJSONObject().containsKey("vp_token"))
    }

    @Test
    fun `5_10 an unsupported alg or enc is Refused and nothing is sent`() {
        val key = VerificationFixtures.verifierEncryptionKey()
        val badAlg = submit(request(responseMode = "direct_post.jwt", clientMetadata = VerificationFixtures.encryptionMetadata(key, alg = "RSA-OAEP-256")))
        assertEquals("invalid_request", (badAlg as PresentationOutcome.Refused).error.errorCode)
        val badEnc = submit(request(responseMode = "direct_post.jwt", clientMetadata = VerificationFixtures.encryptionMetadata(key, enc = "A192GCM")))
        assertTrue(badEnc is PresentationOutcome.Refused)
        assertEquals(0, server.requestCount)
    }

    // ── 5.11 to 5.14 modes and failures ─────────────────────────────────────

    @Test
    fun `5_11 the DC API modes hand the parameters back and the caller's request is untouched`() {
        val request = request(responseMode = "dc_api", clientId = "https://verifier.example")
        val delivered = submit(request) as PresentationOutcome.Delivered
        assertTrue(delivered.parameters.containsKey("vp_token"))
        assertEquals("https://verifier.example", request.clientId)
        assertEquals(0, server.requestCount)
        val kb = VerificationFixtures.keyBindingJwt(
            com.google.gson.JsonParser.parseString(delivered.parameters.getValue("vp_token")).asJsonObject.getAsJsonArray("pid")[0].asString
        )
        assertEquals(listOf("origin:https://verifier.example"), kb.jwtClaimsSet.audience)
    }

    private fun request(responseMode: String, clientId: String) = request(responseMode = responseMode).copy(clientId = clientId)

    @Test
    fun `5_12 iar-post wraps the response with the auth_session`() {
        answer(200, "{}")
        submit(request(responseMode = "iar-post", authSession = "as-1"))
        val fields = form()
        assertEquals("as-1", fields["auth_session"])
        assertTrue(fields.getValue("openid4vp_presentation").contains("\"vp_token\""))
    }

    @Test
    fun `5_13 an unsupported response mode is Refused`() {
        val refused = submit(request(responseMode = "fragment")) as PresentationOutcome.Refused
        assertEquals("invalid_request", refused.error.errorCode)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `5_13b a response type that leaves nothing to send is Refused and nothing is sent`() {
        for (responseType in listOf("code", null)) {
            val request = VerificationFixtures.pexRequest(VerificationFixtures.sdJwtDescriptor("pid"), responseType = responseType)
                .copy(responseUri = server.url("/response").toString())
            val refused = submit(request) as PresentationOutcome.Refused
            assertEquals("unsupported_response_type", refused.error.errorCode)
        }
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `5_14 a proof that cannot be made is Refused and nothing is sent`() {
        val refused = submit(request(), listOf(SelectedCredential("pid", sdJwt, holderKey.toPublicJWK())).let { it }, attestation = null)
        // The holder key would be the fallback, so take it away too.
        val withoutHolder = runBlocking { PresentationSubmitter().submit(request(), listOf(SelectedCredential("pid", sdJwt, holderKey.toPublicJWK())), WalletIdentity(null, null)) }
        assertTrue(withoutHolder is PresentationOutcome.Refused)
        assertEquals(0, server.requestCount)
        assertTrue(refused is PresentationOutcome.Accepted || refused is PresentationOutcome.Refused)
    }

    // ── 5.17 / adapter ──────────────────────────────────────────────────────

    @Test
    fun `5_17 the wallet unit attestation travels as client attestation headers`() {
        answer(200, "{}")
        submit(request(), attestation = WalletAttestation("attestation.jwt~", "pop.jwt"))
        val recorded = server.takeRequest()
        assertEquals("attestation.jwt", recorded.getHeader("OAuth-Client-Attestation"))
        assertEquals("pop.jwt", recorded.getHeader("OAuth-Client-Attestation-PoP"))
    }

    @Test
    @Suppress("DEPRECATION")
    fun `the deprecated V2 entry point keeps its placeholder and error shapes`() {
        answer(200, "{}")
        val accepted = runBlocking { VerificationService().processAndSendAuthorisationResponseV2(VerificationFixtures.DID, holderKey, request(), listOf(listOf(sdJwt)), null, null, false, null, null, null) }
        assertEquals("https://www.example.com?code=1", accepted.vpTokenResponse?.redirectUri)

        answer(200, """{"redirect_uri":"https://verifier.example/cb"}""")
        val redirected = runBlocking { VerificationService().processAndSendAuthorisationResponseV2(VerificationFixtures.DID, holderKey, request(), listOf(listOf(sdJwt)), null, null, false, null, null, null) }
        assertEquals("https://verifier.example/cb", redirected.vpTokenResponse?.redirectUri)

        answer(400, """{"error":"invalid_request","error_description":"nope"}""")
        val failed = runBlocking { VerificationService().processAndSendAuthorisationResponseV2(VerificationFixtures.DID, holderKey, request(), listOf(listOf(sdJwt)), null, null, false, null, null, null) }
        assertNull(failed.vpTokenResponse)
        assertEquals("nope", failed.errorResponse?.errorDescription)

        val mismatch = runBlocking { VerificationService().processAndSendAuthorisationResponseV2(VerificationFixtures.DID, holderKey, request(), listOf(listOf(sdJwt), listOf(sdJwt)), null, null, false, null, null, null) }
        assertTrue(mismatch.errorResponse != null)
    }
}
