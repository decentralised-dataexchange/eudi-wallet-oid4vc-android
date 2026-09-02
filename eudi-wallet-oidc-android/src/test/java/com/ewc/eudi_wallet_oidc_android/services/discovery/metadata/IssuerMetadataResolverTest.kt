package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.runBlocking
import java.util.Date
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

class IssuerMetadataResolverTest {

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

    private val insertionPath = "/.well-known/openid-credential-issuer/tenant"
    private val suffixPath = "/tenant/.well-known/openid-credential-issuer"

    private fun identifier() = server.url("/tenant").toString().trimEnd('/')

    private fun v1Metadata(issuer: String = identifier()) = """
        {
          "credential_issuer": "$issuer",
          "credential_endpoint": "https://issuer.example.com/credential",
          "credential_configurations_supported": { "PidSdJwt": { "format": "dc+sd-jwt" } }
        }
    """.trimIndent()

    /** The shape the EBSI conformance issuer publishes. */
    private fun draftMetadata(issuer: String = identifier()) = """
        {
          "credential_issuer": "$issuer",
          "credential_endpoint": "https://issuer.example.com/credential",
          "authorization_server": "https://as.example.com/auth-mock",
          "credentials_supported": [
            { "format": "jwt_vc", "types": ["VerifiableCredential", "VerifiableAttestation"],
              "trust_framework": { "name": "ebsi" } }
          ]
        }
    """.trimIndent()

    private val signingKey: ECKey = ECKeyGenerator(Curve.P_256).generate()

    /** A conformant section 12.2.3 document: correct `typ`, `sub`, `iat`, and a real signature. */
    private fun signedMetadataJwt(): String {
        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("openidvci-issuer-metadata+jwt"))
            .jwk(signingKey.toPublicJWK())
            .build()
        val claims = JWTClaimsSet.Builder()
            .subject(identifier())
            .issueTime(Date())
            .claim("credential_issuer", identifier())
            .claim("credential_endpoint", "https://issuer.example.com/credential")
            .claim("credential_configurations_supported", mapOf("PidSdJwt" to mapOf("format" to "dc+sd-jwt")))
            .build()
        return SignedJWT(header, claims).apply { sign(ECDSASigner(signingKey)) }.serialize()
    }

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

    /** Defaults match production: the SDK's own [SignatureValidatorSignedMetadataVerifier]. */
    private fun resolve(
        policy: DiscoveryPolicy = httpAllowed(DiscoveryPolicy.Default),
        verifier: SignedMetadataVerifier = SignatureValidatorSignedMetadataVerifier(),
        input: String = identifier(),
    ) = runBlocking { IssuerMetadataResolver(policy = policy, signedMetadataVerifier = verifier).resolve(input) }

    /** MockWebServer speaks http, so every policy under test has to permit it. */
    private fun httpAllowed(policy: DiscoveryPolicy) = policy.copy(allowedSchemes = setOf("http", "https"))

    @Test
    fun `the spec insertion url is tried first`() {
        serve(insertionPath to json(v1Metadata()))

        val result = resolve()

        assertNotNull(result.response.issuerConfig)
        assertEquals(WellKnownForm.Insertion, result.diagnostics.form)
        assertEquals(IssuerMetadataSpecVersion.V1_0, result.diagnostics.specVersion)
        assertFalse(result.diagnostics.usedSuffixFallback)
        assertEquals(insertionPath, server.takeRequest().path)
    }

    /** EBSI's own layout: the spec URL 404s and only the suffix form answers. */
    @Test
    fun `a 404 on the spec url falls back to the suffix url`() {
        serve(suffixPath to json(draftMetadata()))

        val result = resolve()

        assertNotNull(result.response.issuerConfig)
        assertEquals(WellKnownForm.Suffix, result.diagnostics.form)
        assertEquals(IssuerMetadataSpecVersion.Draft, result.diagnostics.specVersion)
        assertTrue(result.diagnostics.usedSuffixFallback)
        assertEquals(2, result.diagnostics.attemptedUrls.size)
    }

    @Test
    fun `strict policy does not try the suffix url`() {
        serve(suffixPath to json(v1Metadata()))

        val result = resolve(policy = httpAllowed(DiscoveryPolicy.Strict))

        assertNull(result.response.issuerConfig)
        assertEquals(1, result.diagnostics.attemptedUrls.size)
    }

    @Test
    fun `strict policy rejects draft metadata`() {
        serve(insertionPath to json(draftMetadata()))

        val result = resolve(policy = httpAllowed(DiscoveryPolicy.Strict))

        assertNull(result.response.issuerConfig)
        assertTrue(result.response.errorResponse?.errorDescription!!.contains("pre-1.0"))
    }

    /**
     * The old implementation reported whichever URL happened to be tried last, so a 403 on the
     * URL the issuer actually uses was masked by a 404 on the fallback.
     */
    @Test
    fun `a definite error outranks a 404 from another url`() {
        serve(insertionPath to MockResponse().setResponseCode(403).setBody("forbidden"))

        val result = resolve()

        assertNull(result.response.issuerConfig)
        assertEquals(403, result.response.errorResponse?.error)
    }

    /** Signed metadata is verified, never decoded and trusted. An unsigned JWT has no signature. */
    @Test
    fun `an unsigned jwt is rejected rather than decoded`() {
        val unsignedJwt = "eyJhbGciOiJub25lIn0." +
            "eyJjcmVkZW50aWFsX2lzc3VlciI6Imh0dHBzOi8vYXR0YWNrZXIuZXhhbXBsZS5jb20ifQ."
        serve(insertionPath to MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/jwt")
            .setBody(unsignedJwt))

        val result = resolve()

        assertNull(result.response.issuerConfig)
        assertTrue(result.response.errorResponse?.errorDescription!!.contains("unsigned"))
    }

    /** A JWT mislabelled as JSON must still reach the verifier, never be trusted. */
    @Test
    fun `a jwt served as json is still routed to the verifier`() {
        val unsignedJwt = "eyJhbGciOiJub25lIn0.eyJjcmVkZW50aWFsX2lzc3VlciI6IngifQ."
        serve(insertionPath to json(unsignedJwt))

        val result = resolve()

        assertNull(result.response.issuerConfig)
        assertTrue(result.response.errorResponse?.errorDescription!!.contains("unsigned"))
    }

    /** Refusing outright stays available, and is always safe: every issuer must serve JSON too. */
    @Test
    fun `the rejecting verifier refuses signed metadata outright`() {
        serve(insertionPath to MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/jwt")
            .setBody(signedMetadataJwt()))

        val result = resolve(verifier = RejectingSignedMetadataVerifier())

        assertNull(result.response.issuerConfig)
        assertTrue(result.response.errorResponse?.errorDescription!!.contains("cannot verify"))
    }

    /** End to end on the production default: a correctly signed document is used. */
    @Test
    fun `correctly signed metadata is verified and accepted`() {
        serve(insertionPath to MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/jwt")
            .setBody(signedMetadataJwt()))

        val result = resolve()

        assertNotNull(result.response.issuerConfig)
        assertEquals(identifier(), result.response.issuerConfig?.credentialIssuer)
        assertEquals("application/jwt", result.diagnostics.contentType)
    }

    /** Signed by a key that did not produce the signature the document carries. */
    @Test
    fun `signed metadata with a broken signature is refused`() {
        val jwt = signedMetadataJwt()
        val tampered = jwt.substringBeforeLast('.') + "." + "A".repeat(86)
        serve(insertionPath to MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/jwt")
            .setBody(tampered))

        val result = resolve()

        assertNull(result.response.issuerConfig)
        assertTrue(result.response.errorResponse?.errorDescription!!.contains("invalid signature"))
    }

    @Test
    fun `a host-supplied verifier can accept signed metadata`() {
        val payload = v1Metadata()
        val verifier = object : SignedMetadataVerifier {
            override val supportsSignedMetadata = true
            override suspend fun verify(jwt: String, expectedIssuerIdentifier: String) = payload
        }
        serve(insertionPath to MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "application/jwt")
            .setBody("eyJhbGciOiJFUzI1NiJ9.e30.sig"))

        val result = resolve(verifier = verifier)

        assertNotNull(result.response.issuerConfig)
    }

    /**
     * Section 12.2.2 treats Accept as "signaling whether it supports signed metadata", so a wallet
     * that will refuse a signature must not ask for one.
     */
    @Test
    fun `the accept header advertises jwt only when the wallet can verify one`() {
        serve(insertionPath to json(v1Metadata()))
        resolve(verifier = RejectingSignedMetadataVerifier())
        assertEquals("application/json", server.takeRequest().getHeader("Accept"))

        server.shutdown(); server = MockWebServer(); server.start()
        serve(insertionPath to json(v1Metadata()))
        resolve()
        assertEquals("application/json, application/jwt", server.takeRequest().getHeader("Accept"))
    }

    @Test
    fun `an accept-language header is sent and can be overridden`() {
        serve(insertionPath to json(v1Metadata()))
        resolve(policy = httpAllowed(DiscoveryPolicy.Default).copy(acceptLanguage = "sv-SE"))
        assertEquals("sv-SE", server.takeRequest().getHeader("Accept-Language"))
    }

    /**
     * Off by default -- deployed issuers declare a canonical identifier while answering at other
     * paths, so enforcing it rejects working issuers. See [DiscoveryPolicy.requireIssuerIdentifierMatch].
     */
    @Test
    fun `metadata for a different issuer is rejected only when the check is enabled`() {
        serve(insertionPath to json(v1Metadata(issuer = "https://attacker.example.com")))
        assertNotNull(resolve().response.issuerConfig)

        server.shutdown(); server = MockWebServer(); server.start()
        serve(insertionPath to json(v1Metadata(issuer = "https://attacker.example.com")))
        val enforced = resolve(
            policy = httpAllowed(DiscoveryPolicy.Default).copy(requireIssuerIdentifierMatch = true)
        )
        assertNull(enforced.response.issuerConfig)
        assertTrue(enforced.response.errorResponse?.errorDescription!!.contains("different issuer"))
    }

    @Test
    fun `a document matching no known shape is rejected`() {
        serve(insertionPath to json("""{"something_else": true}"""))

        val result = resolve()

        assertNull(result.response.issuerConfig)
        assertTrue(result.response.errorResponse?.errorDescription!!.contains("recognisable"))
    }

    @Test
    fun `malformed json is reported rather than swallowed`() {
        serve(insertionPath to json("{ not json"))

        val result = resolve()

        assertNull(result.response.issuerConfig)
        assertNotNull(result.response.errorResponse?.errorDescription)
    }

    @Test
    fun `an oversized document is refused`() {
        serve(insertionPath to json(v1Metadata()))

        val result = resolve(policy = httpAllowed(DiscoveryPolicy.Default).copy(maxMetadataBytes = 10))

        assertNull(result.response.issuerConfig)
    }

    @Test
    fun `a non-json content type passes by default and fails under strict`() {
        serve(insertionPath to MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "text/plain")
            .setBody(v1Metadata()))
        assertNotNull(resolve().response.issuerConfig)

        server.shutdown(); server = MockWebServer(); server.start()
        serve(insertionPath to MockResponse()
            .setResponseCode(200)
            .setHeader("Content-Type", "text/plain")
            .setBody(v1Metadata()))
        val strict = resolve(policy = httpAllowed(DiscoveryPolicy.Strict))
        assertNull(strict.response.issuerConfig)
    }

    /** Never a bare null: the wallet's error branch has to have something to fire on. */
    @Test
    fun `a blank address reports an error rather than returning null`() {
        val result = runBlocking { IssuerMetadataResolver().resolve(null) }
        assertNull(result.response.issuerConfig)
        assertNotNull(result.response.errorResponse?.errorDescription)
    }

    @Test
    fun `a disallowed scheme is refused before any request`() {
        val result = runBlocking {
            IssuerMetadataResolver().resolve("file:///etc/passwd")
        }
        assertNull(result.response.issuerConfig)
        assertTrue(result.response.errorResponse?.errorDescription!!.contains("unsupported scheme"))
    }
}
