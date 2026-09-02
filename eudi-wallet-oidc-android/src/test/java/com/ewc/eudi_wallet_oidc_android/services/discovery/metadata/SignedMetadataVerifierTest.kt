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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Date

/**
 * OpenID4VCI 1.0 section 12.2.3.
 *
 * The signing key is carried in the JOSE header as a plain JWK, which
 * [com.ewc.eudi_wallet_oidc_android.services.credentialValidation.SignatureValidator] resolves
 * without network access, so these stay offline.
 */
class SignedMetadataVerifierTest {

    private val issuer = "https://issuer.example.com"
    private val key: ECKey = ECKeyGenerator(Curve.P_256).keyID("test-key").generate()

    private fun signedMetadata(
        type: String? = "openidvci-issuer-metadata+jwt",
        subject: String? = issuer,
        issueTime: Date? = Date(),
        expiry: Date? = null,
        signWith: ECKey = key,
    ): String {
        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .apply { type?.let { type(JOSEObjectType(it)) } }
            .jwk(key.toPublicJWK())
            .build()

        val claims = JWTClaimsSet.Builder()
            .apply { subject?.let { subject(it) } }
            .apply { issueTime?.let { issueTime(it) } }
            .apply { expiry?.let { expirationTime(it) } }
            .claim("credential_issuer", issuer)
            .claim("credential_endpoint", "$issuer/credential")
            .claim("credential_configurations_supported", mapOf("PidSdJwt" to mapOf("format" to "dc+sd-jwt")))
            .build()

        return SignedJWT(header, claims).apply { sign(ECDSASigner(signWith)) }.serialize()
    }

    private fun verifier(trusted: Boolean = true) =
        SignatureValidatorSignedMetadataVerifier(trust = { trusted })

    private fun verify(jwt: String, trusted: Boolean = true, expected: String = issuer) =
        runBlocking { verifier(trusted).verify(jwt, expected) }

    private fun assertRejected(contains: String, block: () -> Unit) {
        val error = assertThrows(DiscoveryException.SignedMetadataRejected::class.java) { block() }
        assertTrue(
            "expected a message containing \"$contains\", got \"${error.message}\"",
            error.message!!.contains(contains),
        )
    }

    /**
     * Asserted through a JSON parse rather than string matching: Nimbus escapes `/` as `\/`, which
     * is valid JSON and unescapes on the way back in, and the resolver parses this payload anyway.
     */
    @Test
    fun `a correctly signed and trusted document is accepted`() {
        val payload = com.google.gson.JsonParser.parseString(verify(signedMetadata())).asJsonObject

        assertEquals(issuer, payload.get("credential_issuer").asString)
        assertEquals("$issuer/credential", payload.get("credential_endpoint").asString)
        assertTrue(payload.has("credential_configurations_supported"))
    }

    /** The point of the whole exercise: authentic is not the same as trusted. */
    @Test
    fun `an authentic document from an untrusted signer is rejected`() {
        assertRejected("does not trust") { verify(signedMetadata(), trusted = false) }
    }

    @Test
    fun `a tampered payload fails the signature check`() {
        val jwt = signedMetadata()
        val (header, _, signature) = jwt.split(".")
        // Well-formed and complete -- only the signature no longer matches. If claim checks ran
        // before the signature check, this would be reported as some other problem.
        val forged = com.nimbusds.jose.util.Base64URL.encode(
            """{"sub":"$issuer","iat":${System.currentTimeMillis() / 1000},"credential_issuer":"https://attacker.example.com"}"""
        ).toString()
        assertRejected("invalid signature") { verify("$header.$forged.$signature") }
    }

    /** Signed by a real key, but not the one the header advertises. */
    @Test
    fun `a document signed by a different key is rejected`() {
        val other = ECKeyGenerator(Curve.P_256).generate()
        assertRejected("invalid signature") { verify(signedMetadata(signWith = other)) }
    }

    @Test
    fun `an unsigned jwt is rejected before anything else`() {
        val unsigned = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSJ9."
        assertRejected("unsigned") { verify(unsigned) }
    }

    /** typ: REQUIRED. MUST be openidvci-issuer-metadata+jwt. */
    @Test
    fun `a wrong or missing typ is rejected`() {
        assertRejected("not typed") { verify(signedMetadata(type = "JWT")) }
        assertRejected("not typed") { verify(signedMetadata(type = null)) }
    }

    /** sub: REQUIRED. String matching the Credential Issuer Identifier. */
    @Test
    fun `a sub naming another issuer is rejected`() {
        assertRejected("different issuer") {
            verify(signedMetadata(subject = "https://attacker.example.com"))
        }
    }

    @Test
    fun `a document fetched for a different issuer is rejected`() {
        assertRejected("different issuer") {
            verify(signedMetadata(), expected = "https://elsewhere.example.com")
        }
    }

    @Test
    fun `a missing sub is rejected`() {
        assertRejected("does not name an issuer") { verify(signedMetadata(subject = null)) }
    }

    /** iat: REQUIRED. */
    @Test
    fun `a missing iat is rejected`() {
        assertRejected("not dated") { verify(signedMetadata(issueTime = null)) }
    }

    /** exp: OPTIONAL, but honoured when present. */
    @Test
    fun `an expired document is rejected and clock skew is allowed`() {
        val longAgo = Date(System.currentTimeMillis() - 3_600_000)
        assertRejected("expired") { verify(signedMetadata(expiry = longAgo)) }

        val justNow = Date(System.currentTimeMillis() - 5_000)
        verify(signedMetadata(expiry = justNow))
    }

    @Test
    fun `the default verifier refuses everything`() {
        assertRejected("cannot verify") {
            runBlocking { RejectingSignedMetadataVerifier().verify(signedMetadata(), issuer) }
        }
    }
}
