package com.ewc.eudi_wallet_oidc_android.services.issue

import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.v2.IssuerWellKnownConfigurationV2
import com.ewc.eudi_wallet_oidc_android.services.utils.ProofService
import com.google.gson.Gson
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.SignedJWT
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BatchCredentialIssuanceTest {

    @Test
    fun `batch_size is read from 1_0 issuer metadata`() {
        val v2 = Gson().fromJson(
            """{"credential_issuer":"https://issuer","batch_credential_issuance":{"batch_size":5}}""",
            IssuerWellKnownConfigurationV2::class.java
        )
        assertEquals(5, IssuerWellKnownConfiguration(v2).batchCredentialIssuance?.batchSize)
    }

    @Test
    fun `metadata without batch support has no batch size`() {
        val v2 = Gson().fromJson("""{"credential_issuer":"https://issuer"}""", IssuerWellKnownConfigurationV2::class.java)
        assertNull(IssuerWellKnownConfiguration(v2).batchCredentialIssuance)
    }

    @Test
    fun `a credential proof lives for minutes, not seconds`() {
        val key = ECKeyGenerator(Curve.P_256).generate()
        val jwt = ProofService().createProof(
            did = null, subJwk = key, nonce = "n",
            issuerConfig = IssuerWellKnownConfiguration(credentialIssuer = "https://issuer"),
            credentialOffer = null
        )
        assertNotNull(jwt)
        val claims = SignedJWT.parse(jwt).jwtClaimsSet
        val lifetimeMs = claims.expirationTime.time - claims.issueTime.time
        assertTrue("proof lifetime was $lifetimeMs ms", lifetimeMs >= 5 * 60 * 1000)
    }
}
