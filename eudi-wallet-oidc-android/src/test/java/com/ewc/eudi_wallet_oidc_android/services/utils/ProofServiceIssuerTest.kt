package com.ewc.eudi_wallet_oidc_android.services.utils

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.SignedJWT
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class ProofServiceIssuerTest {

    private val bindingKey = ECKeyGenerator(Curve.P_256).generate()
    private val bindingDid = "did:key:zBindingKey"

    @Test
    fun `iss defaults to the DID`() {
        val jwt = ProofService().createProof(bindingDid, bindingKey, "nonce", null, null)
        assertEquals(bindingDid, SignedJWT.parse(jwt).jwtClaimsSet.issuer)
    }

    @Test
    fun `iss can differ from the DID the proof is bound with`() {
        val jwt = ProofService().createProof(bindingDid, bindingKey, "nonce", null, null, issuer = "did:key:zWalletUnit")
        assertEquals("did:key:zWalletUnit", SignedJWT.parse(jwt).jwtClaimsSet.issuer)
    }

    @Test
    fun `a null issuer omits iss`() {
        val jwt = ProofService().createProof(bindingDid, bindingKey, "nonce", null, null, issuer = null)
        assertFalse(SignedJWT.parse(jwt).jwtClaimsSet.claims.containsKey("iss"))
    }
}
