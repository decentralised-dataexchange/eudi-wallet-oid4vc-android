package com.ewc.eudi_wallet_oidc_android.services.issue.credential.proof

import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.CredentialRequestException
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.CredentialSubject
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Which of section 8.2's two proof shapes a request carries.
 *
 * The rule: **`jwt` whenever the issuer offers `jwt`**, including when `attestation` is offered
 * beside it; `attestation` only when the issuer accepts nothing else. These tests pin the decision
 * itself -- `CredentialRequestParametersTest` covers how each shape is then serialised.
 */
class CredentialProofFactoryTest {

    private val nonce = "c-nonce-1"

    /** A key attestation carrying [nonce], which Appendix F.3 requires for an attestation proof. */
    private fun keyAttestation(carrying: String?): String {
        val key = ECKeyGenerator(Curve.P_256).generate()
        val claims = JWTClaimsSet.Builder()
            .apply { carrying?.let { claim("nonce", it) } }
            .build()
        return SignedJWT(JWSHeader(JWSAlgorithm.ES256), claims)
            .apply { sign(ECDSASigner(key)) }
            .serialize()
    }

    private fun session(vararg proofTypes: String) = IssuanceSession(
        credentialOffer = null,
        issuerConfig = IssuerWellKnownConfiguration(
            credentialIssuer = "https://issuer.example.com",
            credentialsSupported = mapOf(
                "PidSdJwt" to mapOf(
                    "proof_types_supported" to proofTypes.associateWith { emptyMap<String, Any>() },
                ),
            ),
        ),
        authConfig = null,
    )

    private fun createAll(session: IssuanceSession, keyAttestation: String?) =
        CredentialProofFactory.createAll(
            session = session,
            wallet = WalletIdentity("did:key:zBinding", ECKeyGenerator(Curve.P_256).generate()),
            issuer = "did:key:zWallet",
            nonce = nonce,
            subject = CredentialSubject.ByConfiguration("PidSdJwt"),
            keyAttestation = keyAttestation,
        )

    /** The rule the SDK is built on: a signed proof of possession wins wherever it is accepted. */
    @Test
    fun `jwt wins when the issuer offers both proof types`() {
        val proofs = createAll(session("jwt", "attestation"), keyAttestation(nonce))

        assertTrue("expected jwt proofs, got $proofs", proofs is CredentialProofs.Jwt)
        assertEquals(1, (proofs as CredentialProofs.Jwt).proofs.size)
    }

    /** With no `attestation` on offer there is nothing to choose; the jwt proof is the only shape. */
    @Test
    fun `jwt is used when the issuer offers only jwt`() {
        assertTrue(createAll(session("jwt"), keyAttestation(nonce)) is CredentialProofs.Jwt)
    }

    /** ARF TS3 section 2.2.2: only then does the key attestation stand as the proof itself. */
    @Test
    fun `only attestation makes the key attestation the proof`() {
        val ka = keyAttestation(nonce)

        val proofs = createAll(session("attestation"), ka)

        assertEquals(CredentialProofs.Attestation(ka), proofs)
    }

    /** No attestation to send and no jwt proof the issuer would accept: fail before the round trip. */
    @Test
    fun `attestation-only with no key attestation fails before the request`() {
        val failure = assertThrows(CredentialRequestException.ProofFailed::class.java) {
            createAll(session("attestation"), null)
        }
        assertTrue(failure.message.orEmpty().contains("no key attestation"))
    }

    /** Appendix F.3: the issuer's current c_nonce lives inside the attestation, and is checked here. */
    @Test
    fun `attestation-only with a stale nonce fails before the request`() {
        val failure = assertThrows(CredentialRequestException.ProofFailed::class.java) {
            createAll(session("attestation"), keyAttestation("a-stale-nonce"))
        }
        assertTrue(failure.message.orEmpty().contains("c_nonce"))
    }

    /** A batch is one proof per key, each signed by its own; the shape stays `jwt`. */
    @Test
    fun `additional keys make a batch of jwt proofs`() {
        val proofs = CredentialProofFactory.createAll(
            session = session("jwt"),
            wallet = WalletIdentity("did:key:zBinding", ECKeyGenerator(Curve.P_256).generate()),
            additionalKeys = listOf(ECKeyGenerator(Curve.P_256).generate()),
            issuer = "did:key:zWallet",
            nonce = nonce,
            subject = CredentialSubject.ByConfiguration("PidSdJwt"),
        )

        val jwt = proofs as CredentialProofs.Jwt
        assertEquals(2, jwt.proofs.size)
        assertTrue("each key must sign its own proof", jwt.proofs.toSet().size == 2)
        assertTrue(proofs.isBatch)
    }
}
