package com.ewc.eudi_wallet_oidc_android.services.verification.request

import com.ewc.eudi_wallet_oidc_android.models.ClientMetaDetails
import com.ewc.eudi_wallet_oidc_android.models.ErrorCodes
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationService
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.URLEncoder

/**
 * One case per row of the leg 1 matrix in VERIFICATION_REVAMP_PLAN_ANDROID.md, plus registry
 * order and the deprecated adapter. Row 1.10 (`request_uri_method=post`) lives in
 * RequestUriMethodFetchTest, which drives the same resolver.
 *
 * Every fetch goes through the real Retrofit/OkHttp stack against MockWebServer, which works
 * without production changes because every endpoint uses an absolute @Url.
 */
class PresentationRequestResolverTest {

    private lateinit var server: MockWebServer
    private val responses = mutableMapOf<String, MockResponse>()

    /** A redirect_uri client: the one prefix whose requests carry no signature to verify, so the request rows stay about requests. */
    private val clientId = "redirect_uri:${VerificationFixtures.RESPONSE_URI}"
    private val x509ClientId = VerificationFixtures.CLIENT_ID
    private val dcqlJson =
        """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]}]}"""
    private val pdJson =
        """{"id":"pd1","input_descriptors":[{"id":"d1","constraints":{"fields":[{"path":["${'$'}.vct"]}]}}]}"""

    @Before
    fun start() {
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse =
                responses[request.path?.substringBefore('?')] ?: MockResponse().setResponseCode(404)
        }
        server.start()
    }

    @After
    fun stop() = server.shutdown()

    // ── helpers ─────────────────────────────────────────────────────────────

    private fun enc(value: String) = URLEncoder.encode(value, "UTF-8")

    private fun link(vararg params: Pair<String, String>) =
        "openid4vp://?" + params.joinToString("&") { (k, v) -> "$k=${enc(v)}" }

    private fun url(path: String) = server.url(path).toString()

    private fun serve(path: String, body: String, code: Int = 200, contentType: String = "application/json") {
        responses[path] = MockResponse().setResponseCode(code).setHeader("Content-Type", contentType).setBody(body)
    }

    private fun claims(clientId: String = this.clientId, nonce: String = "n1"): Map<String, Any?> = mapOf(
        "client_id" to clientId,
        "response_type" to "vp_token",
        "response_mode" to "direct_post",
        "response_uri" to VerificationFixtures.RESPONSE_URI,
        "nonce" to nonce,
        "dcql_query" to mapOf(
            "credentials" to listOf(
                mapOf("id" to "pid", "format" to "dc+sd-jwt", "meta" to mapOf("vct_values" to listOf("urn:eudi:pid:1")))
            )
        ),
    )

    private fun signedRequestObject(clientId: String = this.clientId) = VerificationFixtures.signedJwt(claims(clientId))

    private fun unsignedRequestObject(clientId: String = this.clientId): String {
        val builder = JWTClaimsSet.Builder()
        claims(clientId).forEach { (k, v) -> builder.claim(k, v) }
        return PlainJWT(builder.build()).serialize()
    }

    private fun resolve(data: String?, policy: PresentationRequestPolicy = PresentationRequestPolicy.Default) =
        runBlocking { PresentationRequestResolver(policy).resolve(data) }

    private fun resolved(outcome: PresentationRequestOutcome): PresentationRequestOutcome.Resolved =
        outcome as? PresentationRequestOutcome.Resolved
            ?: throw AssertionError("expected Resolved, got $outcome")

    private fun failed(outcome: PresentationRequestOutcome): PresentationRequestOutcome.Failed =
        outcome as? PresentationRequestOutcome.Failed
            ?: throw AssertionError("expected Failed, got $outcome")

    @Suppress("DEPRECATION")
    private fun adapter(data: String?) = runBlocking { VerificationService().processAuthorisationRequest(data) }

    // ── 1.1 ─────────────────────────────────────────────────────────────────

    @Test
    fun `1_1 blank input is Failed on the new API and null on the adapter`() {
        for (input in listOf(null, "", "   ")) {
            val failure = failed(resolve(input))
            assertEquals("This QR code does not contain a presentation request", failure.error.errorDescription)
            assertNull(adapter(input))
        }
    }

    // ── 1.2 / 1.3 by value ──────────────────────────────────────────────────

    @Test
    fun `1_2 a dcql_query by value resolves as 1_0`() {
        val outcome = resolved(resolve(link("client_id" to clientId, "nonce" to "n1", "dcql_query" to dcqlJson)))
        assertEquals(PresentationRequestSpecVersion.V1_0, outcome.specVersion)
        assertEquals("by_value", outcome.source)
        assertEquals(clientId, outcome.request.clientId)
        assertEquals("pid", outcome.request.dcqlQuery?.credentials?.single()?.id)
    }

    @Test
    fun `1_3 a presentation_definition by value resolves as Draft and is refused by the strict policy`() {
        val data = link("client_id" to clientId, "nonce" to "n1", "response_type" to "vp_token", "presentation_definition" to pdJson)
        val outcome = resolved(resolve(data))
        assertEquals(PresentationRequestSpecVersion.Draft, outcome.specVersion)
        assertEquals(pdJson, outcome.request.presentationDefinition)

        val strict = failed(resolve(data, PresentationRequestPolicy.Strict))
        assertEquals("This presentation request uses a draft format that is not supported", strict.error.errorDescription)
    }

    // ── 1.4 / 1.5 draft URIs ────────────────────────────────────────────────

    @Test
    fun `1_4 presentation_definition_uri is fetched and a failed fetch fails the request`() {
        serve("/pd", pdJson)
        val ok = resolved(resolve(link("client_id" to clientId, "response_type" to "vp_token", "presentation_definition_uri" to url("/pd"))))
        assertEquals(PresentationRequestSpecVersion.Draft, ok.specVersion)
        assertEquals("pd1", (ok.request.presentationDefinition as PresentationDefinition).id)

        val failure = failed(resolve(link("client_id" to clientId, "response_type" to "vp_token", "presentation_definition_uri" to url("/missing"))))
        assertTrue(failure.error.errorDescription!!.startsWith("The presentation definition could not be fetched"))
    }

    @Test
    fun `1_5 client_metadata_uri is fetched and a failed fetch is not fatal`() {
        serve("/cm", """{"client_name":"Verifier"}""")
        val ok = resolved(resolve(link("client_id" to clientId, "dcql_query" to dcqlJson, "client_metadata_uri" to url("/cm"))))
        assertEquals("Verifier", (ok.request.clientMetaDetails as ClientMetaDetails).clientName)

        val tolerated = resolved(resolve(link("client_id" to clientId, "dcql_query" to dcqlJson, "client_metadata_uri" to url("/missing"))))
        assertNull(tolerated.request.clientMetaDetails)
    }

    // ── 1.6 ─────────────────────────────────────────────────────────────────

    @Test
    fun `1_6 dcql_query wins over a presentation_definition sent beside it`() {
        val outcome = resolved(resolve(link(
            "client_id" to clientId,
            "dcql_query" to dcqlJson,
            "presentation_definition" to pdJson,
            "presentation_definition_uri" to url("/never"),
        )))
        assertEquals(PresentationRequestSpecVersion.V1_0, outcome.specVersion)
        assertNull(outcome.request.presentationDefinition)
        assertNull(outcome.request.presentationDefinitionUri)
        assertEquals(0, server.requestCount)
    }

    // ── 1.7 / 1.8 / 1.9 / 1.11 request_uri ──────────────────────────────────

    @Test
    fun `1_7 a signed request object behind request_uri resolves and is fetched by GET`() {
        val jwt = signedRequestObject()
        serve("/request", jwt, contentType = "application/oauth-authz-req+jwt")
        val outcome = resolved(resolve(link("client_id" to clientId, "request_uri" to url("/request"))))
        assertEquals("GET", server.takeRequest().method)
        assertEquals("request_uri", outcome.source)
        assertEquals(PresentationRequestSpecVersion.V1_0, outcome.specVersion)
        assertEquals(jwt, outcome.request.request)
        assertEquals("n1", outcome.request.nonce)
    }

    @Test
    fun `1_8 a plain JSON body behind request_uri is tolerated`() {
        serve("/request", """{"client_id":"$clientId","nonce":"n1","dcql_query":$dcqlJson}""")
        val outcome = resolved(resolve(link("client_id" to clientId, "request_uri" to url("/request"))))
        assertEquals("n1", outcome.request.nonce)
        assertNull(outcome.request.request)
    }

    @Test
    fun `1_9 an unsigned request object is refused unless the prefix is redirect_uri or the policy allows it`() {
        serve("/request", unsignedRequestObject(x509ClientId), contentType = "application/oauth-authz-req+jwt")
        val data = link("client_id" to x509ClientId, "request_uri" to url("/request"))
        assertEquals("Request validation failed", failed(resolve(data)).error.errorDescription)
        // Unsigned objects allowed, but x509_san_dns still has nothing to verify against.
        val allowed = failed(resolve(data, PresentationRequestPolicy(allowUnsignedRequestObjects = true)))
        assertTrue(allowed.error.errorDescription!!.startsWith("The verifier could not be authenticated"))

        serve("/request", unsignedRequestObject(), contentType = "application/oauth-authz-req+jwt")
        resolved(resolve(link("client_id" to clientId, "request_uri" to url("/request"))))
    }

    @Test
    fun `1_11 an unknown request_uri_method falls back to GET`() {
        serve("/request", signedRequestObject(), contentType = "application/oauth-authz-req+jwt")
        resolved(resolve(link("client_id" to clientId, "request_uri" to url("/request"), "request_uri_method" to "put")))
        assertEquals("GET", server.takeRequest().method)
    }

    // ── 1.12 / 1.13 request object by value ─────────────────────────────────

    @Test
    fun `1_12 a request parameter carrying a JWT resolves and anything else is refused`() {
        val jwt = signedRequestObject()
        val outcome = resolved(resolve(link("client_id" to clientId, "request" to jwt)))
        assertEquals("request", outcome.source)
        assertEquals(jwt, outcome.request.request)
        assertEquals("n1", outcome.request.nonce)

        assertEquals("Invalid Request", failed(resolve(link("client_id" to clientId, "request" to "not-a-jwt"))).error.errorDescription)
    }

    @Test
    fun `1_13 a bare JWT scanned on its own resolves`() {
        val jwt = signedRequestObject()
        val outcome = resolved(resolve(jwt))
        assertEquals("request", outcome.source)
        assertEquals(jwt, outcome.request.request)
        assertEquals(clientId, outcome.request.clientId)
    }

    // ── 1.14 interactive authorization request ─────────────────────────────

    @Test
    fun `1_14 an openid4vp_request keeps the issuer client_id and the session parameters`() {
        val inner = signedRequestObject(clientId = "x509_san_dns:inner.example")
        val wrapper = """{"client_id":"https://issuer.example","request":"$inner"}"""
        val outcome = resolved(resolve(link(
            "openid4vp_request" to wrapper, "auth_session" to "s1", "status" to "pending", "type" to "pid",
        )))
        assertEquals("openid4vp_request", outcome.source)
        assertEquals("https://issuer.example", outcome.request.clientId)
        assertEquals("s1", outcome.request.authSession)
        assertEquals("pending", outcome.request.status)
        assertEquals("pid", outcome.request.type)
        assertEquals("n1", outcome.request.nonce)
        assertEquals(inner, outcome.request.request)
    }

    // ── 1.15 / 1.16 the two RFC 9101 rules ──────────────────────────────────

    @Test
    fun `1_15 request and request_uri together are refused before anything is fetched`() {
        serve("/request", signedRequestObject(), contentType = "application/oauth-authz-req+jwt")
        val data = link("client_id" to clientId, "request" to signedRequestObject(), "request_uri" to url("/request"))

        val failure = failed(resolve(data))
        assertEquals(PresentationRequestException.INVALID_REQUEST, failure.error.errorCode)
        assertEquals(0, server.requestCount)

        resolved(resolve(data, PresentationRequestPolicy(rejectAmbiguousRequests = false)))
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `1_16 a client_id that differs between the URI and the request object is refused`() {
        serve("/request", signedRequestObject(), contentType = "application/oauth-authz-req+jwt")
        val mismatch = failed(resolve(link("client_id" to "x509_san_dns:other.example", "request_uri" to url("/request"))))
        assertEquals(PresentationRequestException.INVALID_REQUEST, mismatch.error.errorCode)
        assertEquals("The client_id in the request does not match the request object", mismatch.error.errorDescription)

        // No client_id in the URI: nothing to compare, the request object stands on its own.
        resolved(resolve(link("request_uri" to url("/request"))))

        val byValue = failed(resolve(link("client_id" to "x509_san_dns:other.example", "request" to signedRequestObject())))
        assertEquals(PresentationRequestException.INVALID_REQUEST, byValue.error.errorCode)
    }

    // ── 1.17 / 1.18 / 1.19 / 1.20 ───────────────────────────────────────────

    @Test
    fun `1_17 an invalid dcql_query is refused with its own error code`() {
        val notJson = failed(resolve(link("client_id" to clientId, "dcql_query" to "{not json")))
        assertEquals(ErrorCodes.INVALID_DCQL_QUERY, notJson.error.error)

        val noId = failed(resolve(link("client_id" to clientId, "dcql_query" to """{"credentials":[{"format":"dc+sd-jwt"}]}""")))
        assertEquals(ErrorCodes.INVALID_DCQL_QUERY, noId.error.error)
        assertTrue(noId.error.errorDescription!!.startsWith("Invalid DCQL query: "))
    }

    @Test
    fun `1_18 an HTTP error or an empty body from request_uri is a failure`() {
        serve("/request", """{"error":"invalid_request","error_description":"refused"}""", code = 400)
        val refused = failed(resolve(link("client_id" to clientId, "request_uri" to url("/request"))))
        assertTrue(refused.error.errorDescription!!.contains("refused"))

        serve("/request", "", contentType = "application/oauth-authz-req+jwt")
        val empty = failed(resolve(link("client_id" to clientId, "request_uri" to url("/request"))))
        assertEquals("Response is null or empty.", empty.error.errorDescription)
    }

    @Test
    fun `1_19 data with none of the known parameters is not a request`() {
        for (input in listOf("openid4vp://?foo=bar", "hello world", "https://example.com/page")) {
            assertEquals(
                "This QR code does not contain a presentation request",
                failed(resolve(input)).error.errorDescription,
            )
        }
    }

    @Test
    fun `1_20 response_mode is carried through as a string`() {
        val outcome = resolved(resolve(link("client_id" to clientId, "dcql_query" to dcqlJson, "response_mode" to "direct_post.jwt")))
        assertEquals("direct_post.jwt", outcome.request.responseMode)
    }

    @Test
    fun `1_21 a presentation definition request is refused unless its response type can be answered`() {
        fun pex(vararg extra: Pair<String, String>) =
            resolve(link("client_id" to clientId, "nonce" to "n1", "presentation_definition" to pdJson, *extra))

        for (type in listOf("vp_token", "id_token", "vp_token id_token", "vp_token+id_token")) {
            assertEquals(PresentationRequestSpecVersion.Draft, resolved(pex("response_type" to type)).specVersion)
        }
        val unknown = failed(pex("response_type" to "code"))
        assertEquals(PresentationRequestException.UNSUPPORTED_RESPONSE_TYPE, unknown.error.errorCode)
        assertEquals("The response type 'code' is not supported", unknown.error.errorDescription)
        val missing = failed(pex())
        assertEquals(PresentationRequestException.UNSUPPORTED_RESPONSE_TYPE, missing.error.errorCode)
        assertEquals("The request names no response type", missing.error.errorDescription)

        // 1.0 always answers with vp_token, so a DCQL request is not checked.
        resolved(resolve(link("client_id" to clientId, "nonce" to "n1", "response_type" to "code", "dcql_query" to dcqlJson)))
    }

    // ── registry and adapter ────────────────────────────────────────────────

    @Test
    fun `the registry tries the by value source before the extension`() {
        val outcome = resolved(resolve(link(
            "client_id" to clientId,
            "dcql_query" to dcqlJson,
            "openid4vp_request" to """{"client_id":"https://issuer.example"}""",
        )))
        assertEquals("by_value", outcome.source)
        assertEquals(clientId, outcome.request.clientId)
    }

    @Test
    fun `the deprecated adapter returns the same request as the new API`() {
        val jwt = signedRequestObject()
        serve("/request", jwt, contentType = "application/oauth-authz-req+jwt")
        val links = listOf(
            link("client_id" to clientId, "nonce" to "n1", "dcql_query" to dcqlJson),
            link("client_id" to clientId, "nonce" to "n1", "response_type" to "vp_token", "presentation_definition" to pdJson),
            link("client_id" to clientId, "request_uri" to url("/request")),
            link("openid4vp_request" to """{"client_id":"https://issuer.example","request":"$jwt"}""", "auth_session" to "s1"),
        )
        for (data in links) {
            val expected = resolved(resolve(data)).request
            val wrapped = adapter(data) ?: throw AssertionError("adapter returned null for $data")
            assertNull(wrapped.errorResponse)
            assertEquals(expected, wrapped.presentationRequest)
        }

        val failure = adapter(link("client_id" to clientId, "dcql_query" to "{not json"))
        assertNotNull(failure?.errorResponse)
        assertNull(failure?.presentationRequest)
        assertEquals(ErrorCodes.INVALID_DCQL_QUERY, failure?.errorResponse?.error)
    }
}
