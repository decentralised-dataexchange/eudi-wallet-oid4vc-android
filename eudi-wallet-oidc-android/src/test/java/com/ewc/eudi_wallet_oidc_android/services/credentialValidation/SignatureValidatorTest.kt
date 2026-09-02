package com.ewc.eudi_wallet_oidc_android.services.credentialValidation

import com.ewc.eudi_wallet_oidc_android.services.exceptions.SignatureException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Offline coverage for [SignatureValidator]: keys come from the JOSE header or from a `did:jwk`,
 * both of which resolve without network access.
 */
class SignatureValidatorTest {

    private val validator = SignatureValidator()
    private val key: ECKey = ECKeyGenerator(Curve.P_256).generate()

    private fun didJwk(key: ECKey): String =
        "did:jwk:" + Base64URL.encode(key.toPublicJWK().toJSONString()).toString()

    private fun sign(header: JWSHeader, signWith: ECKey = key): String =
        SignedJWT(header, JWTClaimsSet.Builder().subject("test").build())
            .apply { sign(ECDSASigner(signWith)) }
            .serialize()

    @Test
    fun `a jwt signed by the key in its header verifies`() {
        val jwt = sign(JWSHeader.Builder(JWSAlgorithm.ES256).jwk(key.toPublicJWK()).build())
        assertTrue(runBlocking { validator.validateSignature(jwt) })
    }

    @Test
    fun `a jwt signed by the key its did-jwk kid names verifies`() {
        val jwt = sign(JWSHeader.Builder(JWSAlgorithm.ES256).keyID(didJwk(key)).build())
        assertTrue(runBlocking { validator.validateSignature(jwt) })
    }

    /**
     * Regression: the candidate-key loop used to abort on the first key that *threw* rather than
     * returned false. Here the header JWK is an RSA key -- the wrong type for ES256, so building a
     * verifier for it throws -- while the `did:jwk` kid names the key that actually signed. Before
     * the fix the RSA key ended the loop and this failed; resolving several candidates was
     * effectively "try the first one".
     */
    @Test
    fun `a candidate key of the wrong type does not stop later candidates being tried`() {
        val wrongType: RSAKey = RSAKeyGenerator(2048).generate()
        val jwt = sign(
            JWSHeader.Builder(JWSAlgorithm.ES256)
                .jwk(wrongType.toPublicJWK())
                .keyID(didJwk(key))
                .build()
        )
        assertTrue(runBlocking { validator.validateSignature(jwt) })
    }

    @Test
    fun `a jwt signed by an unrelated key is rejected`() {
        val other = ECKeyGenerator(Curve.P_256).generate()
        val jwt = sign(JWSHeader.Builder(JWSAlgorithm.ES256).jwk(key.toPublicJWK()).build(), signWith = other)
        assertThrows(SignatureException::class.java) {
            runBlocking { validator.validateSignature(jwt) }
        }
    }

    @Test
    fun `an unsecured jwt is rejected rather than treated as unverifiable`() {
        val unsigned = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0."
        val error = assertThrows(SignatureException::class.java) {
            runBlocking { validator.validateSignature(unsigned) }
        }
        assertTrue(error.message!!.contains("unsigned"))
    }

    @Test
    fun `a null jwt is rejected`() {
        assertThrows(SignatureException::class.java) {
            runBlocking { validator.validateSignature(null) }
        }
    }

    @Test
    fun `verifyJwtSignature returns false for a valid key that did not sign`() {
        val other = ECKeyGenerator(Curve.P_256).generate()
        val jwt = sign(JWSHeader.Builder(JWSAlgorithm.ES256).build())
        assertFalse(validator.verifyJwtSignature(jwt, other.toPublicJWK().toJSONString()))
    }
}
