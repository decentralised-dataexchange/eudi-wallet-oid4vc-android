package com.ewc.eudi_wallet_oidc_android.services.verification

import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestOutcome
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestResolver
import com.google.gson.JsonParser
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.jwk.ECKey
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
import java.net.URLDecoder
import java.net.URLEncoder

/**
 * OpenID4VP 1.0 section 5.10 and 5.10.1, exercised through the real fetch path against a mock
 * verifier: what the wallet sends, and what it does with each kind of answer.
 *
 * The mock verifier uses the `redirect_uri` client identifier prefix, whose request object is
 * unsigned by definition (section 5.9), so the fetch path can run on the JVM without the
 * certificate handling the x509 prefixes need. The method, nonce and encryption rules under test
 * do not depend on the prefix.
 */
class RequestUriMethodFetchTest {

    private lateinit var server: MockWebServer
    private val clientId = "redirect_uri:https://verifier.example/response"
    private val requestUri get() = server.url("/request/1").toString()

    @Before
    fun start() { server = MockWebServer(); server.start() }

    @After
    fun stop() { server.shutdown() }

    private fun authorisationRequest(method: String? = null): String {
        val uri = URLEncoder.encode(requestUri, "UTF-8")
        val suffix = method?.let { "&request_uri_method=$it" } ?: ""
        val client = URLEncoder.encode(clientId, "UTF-8")
        return "openid4vp://?client_id=$client&request_uri=$uri$suffix"
    }

    /** A request object, optionally echoing [walletNonce], as the verifier would mint it. */
    private fun requestObject(walletNonce: String?): String {
        val claims = JWTClaimsSet.Builder()
            .claim("client_id", clientId)
            .claim("response_type", "vp_token")
            .claim("response_mode", "direct_post")
            .claim("response_uri", "https://verifier.example/response")
            .claim("nonce", "n-verifier")
            .claim(
                "dcql_query",
                mapOf(
                    "credentials" to listOf(
                        mapOf(
                            "id" to "pid",
                            "format" to "dc+sd-jwt",
                            "meta" to mapOf("vct_values" to listOf("urn:eudi:pid:1")),
                            "claims" to listOf(mapOf("path" to listOf("family_name")))
                        )
                    )
                )
            )
            .apply { if (walletNonce != null) claim("wallet_nonce", walletNonce) }
            .build()
        return PlainJWT(claims).serialize()
    }

    private fun form(request: RecordedRequest): Map<String, String> =
        request.body.clone().readUtf8().split('&').filter { it.isNotBlank() }.associate {
            URLDecoder.decode(it.substringBefore('='), "UTF-8") to URLDecoder.decode(it.substringAfter('='), "UTF-8")
        }

    /** Answers the way a section 5.10 verifier does: echoes the nonce, encrypts when asked. */
    private fun verifier(echoNonce: Boolean = true, encrypt: Boolean = false, status: Int = 200) {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                if (status != 200) {
                    return MockResponse().setResponseCode(status)
                        .setHeader("Content-Type", "application/json")
                        .setBody("""{"error":"invalid_request","error_description":"refused"}""")
                }
                val fields = if (request.method == "POST") form(request) else emptyMap()
                val nonce = fields["wallet_nonce"]?.takeIf { echoNonce }
                var body = requestObject(nonce)
                if (encrypt) {
                    val jwks = JsonParser.parseString(fields.getValue("wallet_metadata")).asJsonObject
                        .getAsJsonObject("jwks").getAsJsonArray("keys")[0].toString()
                    val walletKey = ECKey.parse(jwks)
                    body = JWEObject(
                        JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM)
                            .type(JOSEObjectType("oauth-authz-req+jwt")).contentType("JWT")
                            .keyID(walletKey.keyID).build(),
                        Payload(body)
                    ).apply { encrypt(ECDHEncrypter(walletKey)) }.serialize()
                }
                return MockResponse().setResponseCode(200)
                    .setHeader("Content-Type", "application/oauth-authz-req+jwt")
                    .setBody(body)
            }
        }
    }

    private fun fetch(method: String?): WrappedPresentationRequest = runBlocking {
        when (val outcome = PresentationRequestResolver().resolve(authorisationRequest(method))) {
            is PresentationRequestOutcome.Resolved -> WrappedPresentationRequest(presentationRequest = outcome.request)
            is PresentationRequestOutcome.Failed -> WrappedPresentationRequest(errorResponse = outcome.error)
        }
    }

    @Test
    fun `without request_uri_method the request object is fetched by GET`() {
        verifier()
        val result = fetch(method = null)
        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals(0L, recorded.bodySize)
        assertNull(result.errorResponse)
        assertEquals(clientId, result.presentationRequest?.clientId)
    }

    @Test
    fun `request_uri_method get is a plain GET`() {
        verifier()
        fetch(method = "get")
        assertEquals("GET", server.takeRequest().method)
    }

    @Test
    fun `request_uri_method post sends a form with wallet_metadata and wallet_nonce`() {
        verifier()
        val result = fetch(method = "post")
        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertTrue(recorded.getHeader("Content-Type")!!.startsWith("application/x-www-form-urlencoded"))
        assertEquals("application/oauth-authz-req+jwt", recorded.getHeader("Accept"))
        val fields = form(recorded)
        val metadata = JsonParser.parseString(fields.getValue("wallet_metadata")).asJsonObject
        assertTrue(metadata.has("vp_formats_supported"))
        assertTrue(metadata.getAsJsonObject("jwks").getAsJsonArray("keys").size() == 1)
        assertTrue(fields.getValue("wallet_nonce").length >= 32)
        assertNull(result.errorResponse)
        assertEquals(fields["wallet_nonce"], result.presentationRequest?.walletNonce)
        assertNotNull(result.presentationRequest?.request)
    }

    @Test
    fun `a request object that does not echo the wallet_nonce is refused`() {
        verifier(echoNonce = false)
        val result = fetch(method = "post")
        assertNull(result.presentationRequest)
        assertEquals("Request validation failed", result.errorResponse?.errorDescription)
    }

    @Test
    fun `an encrypted request object is opened and then checked like a plain one`() {
        verifier(encrypt = true)
        val result = fetch(method = "post")
        val sent = form(server.takeRequest()).getValue("wallet_nonce")
        assertNull(result.errorResponse)
        assertEquals(sent, result.presentationRequest?.walletNonce)
        assertEquals(clientId, result.presentationRequest?.clientId)
        // The request object, not the JWE, is what the rest of the flow sees.
        assertEquals(2, result.presentationRequest?.request?.count { it == '.' })
    }

    @Test
    fun `an encrypted request object that drops the nonce is refused`() {
        verifier(echoNonce = false, encrypt = true)
        val result = fetch(method = "post")
        assertNull(result.presentationRequest)
        assertEquals("Request validation failed", result.errorResponse?.errorDescription)
    }

    @Test
    fun `an HTTP error from the verifier terminates the process`() {
        verifier(status = 400)
        val result = fetch(method = "post")
        assertNull(result.presentationRequest)
        assertNotNull(result.errorResponse)
        assertTrue(result.errorResponse?.errorDescription?.contains("refused") == true)
    }
}
