package com.ewc.eudi_wallet_oidc_android.services.issue.credential

import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.Credentials
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.credential.proof.CredentialProofs
import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The credential request body: what each subject puts on the wire, and what it must not. */
class CredentialRequestParametersTest {

    private fun session(
        configuration: Map<String, Any> = emptyMap(),
        nonceEndpoint: String? = null,
        offerVersion: Int? = null,
        credentialsSupported: Any = mapOf("PidSdJwt" to configuration),
    ) = IssuanceSession(
        credentialOffer = offerVersion?.let { CredentialOffer(version = it) },
        issuerConfig = IssuerWellKnownConfiguration(
            credentialIssuer = "https://issuer.example.com",
            credentialsSupported = credentialsSupported,
            nonceEndpoint = nonceEndpoint,
        ),
        authConfig = null,
    )

    private fun body(
        subject: CredentialSubject,
        session: IssuanceSession = session(),
        policy: CredentialRequestPolicy = CredentialRequestPolicy.Default,
        proofs: CredentialProofs = CredentialProofs.Jwt(listOf("the.proof.jwt")),
        token: TokenResponse? = null,
    ) = CredentialRequestParameters.build(
        subject = subject,
        proofs = proofs,
        session = session,
        token = token,
        encryption = null,
        policy = policy,
    )

    private fun assertPlural(request: com.ewc.eudi_wallet_oidc_android.models.CredentialRequest) {
        assertEquals(listOf("the.proof.jwt"), request.proofs?.jwt)
        assertNull(request.proof)
    }

    private fun assertSingular(request: com.ewc.eudi_wallet_oidc_android.models.CredentialRequest) {
        assertEquals("the.proof.jwt", request.proof?.jwt)
        assertEquals("jwt", request.proof?.proofType)
        assertNull(request.proofs)
    }

    /**
     * Section 8.2's `proofs` is an array. A batch is more than one entry, and it takes the plural
     * form whatever the metadata declares -- the singular `proof` cannot express a batch at all.
     */
    @Test
    fun `a batch sends every proof in the plural form`() {
        val body = body(
            CredentialSubject.ByConfiguration("PidSdJwt"),
            proofs = CredentialProofs.Jwt(listOf("proof.one", "proof.two", "proof.three")),
        )

        assertEquals(listOf("proof.one", "proof.two", "proof.three"), body.proofs?.jwt)
        assertNull(body.proof)
    }

    /** The attestation proof type sends the key attestation and no jwt proof at all. */
    @Test
    fun `the attestation proof type sends the key attestation instead of a jwt`() {
        val body = body(
            CredentialSubject.ByConfiguration("PidSdJwt"),
            proofs = CredentialProofs.Attestation("the.key.attestation"),
        )

        assertEquals(listOf("the.key.attestation"), body.proofs?.attestation)
        assertNull(body.proofs?.jwt)
        assertNull(body.proof)
    }

    /**
     * Section 8.2: `credential_identifier` "MUST NOT be used" alongside
     * `credential_configuration_id`, and the mirror rule. A sealed subject makes both-at-once
     * unrepresentable, so this asserts the consequence rather than the guard.
     */
    @Test
    fun `the two identifiers can never travel together`() {
        val byIdentifier = body(CredentialSubject.ByIdentifier("id-1"))
        assertEquals("id-1", byIdentifier.credentialIdentifier)
        assertNull(byIdentifier.credentialConfigurationId)
        assertNull(byIdentifier.format)

        val byConfiguration = body(CredentialSubject.ByConfiguration("PidSdJwt"))
        assertEquals("PidSdJwt", byConfiguration.credentialConfigurationId)
        assertNull(byConfiguration.credentialIdentifier)
        // 1.0 has no `format` in the credential request at all.
        assertNull(byConfiguration.format)
    }

    /** Drafts and EBSI, the one case to delete when draft support goes. */
    @Test
    fun `the legacy subject carries format and the revision's own type field`() {
        val ebsi = body(CredentialSubject.LegacyFormat(format = "jwt_vc", types = listOf("A", "B")))
        assertEquals("jwt_vc", ebsi.format)
        assertEquals(arrayListOf("A", "B"), ebsi.types)
        assertNull(ebsi.credentialIdentifier)
        assertNull(ebsi.credentialConfigurationId)

        val mdoc = body(CredentialSubject.LegacyFormat(format = "mso_mdoc", docType = "org.iso.18013.5.1.mDL"))
        assertEquals("org.iso.18013.5.1.mDL", mdoc.doctype)

        val sdJwt = body(CredentialSubject.LegacyFormat(format = "vc+sd-jwt", vct = "PidSdJwt"))
        assertEquals("PidSdJwt", sdJwt.vct)
    }

    /**
     * Section 8.2 of 1.0 defines only `proofs`, so it is the default. Neither a nonce endpoint nor
     * `proof_types_supported` is required of a 1.0 issuer, so their absence must not demote it.
     */
    @Test
    fun `a 1_0 issuer gets plural proofs without a nonce endpoint or proof_types_supported`() {
        assertPlural(body(CredentialSubject.ByConfiguration("PidSdJwt")))
        assertPlural(body(CredentialSubject.ByConfiguration("PidSdJwt"), session(nonceEndpoint = "https://issuer.example.com/nonce")))
    }

    /**
     * A credential identifier is an instance id, not a metadata key. Looking the configuration up
     * by it found nothing and sent the singular `proof` to 1.0 issuers.
     */
    @Test
    fun `a credential identifier request gets plural proofs`() {
        assertPlural(body(CredentialSubject.ByIdentifier("instance-1")))
    }

    /** The identifier is resolved through the offer entry it was issued for. */
    @Test
    fun `a credential identifier is looked up by its offer entry`() {
        val subject = CredentialSubject.ByIdentifier(
            "instance-1",
            offerCredential = Credentials(types = arrayListOf("PidSdJwt")),
        )

        assertEquals("PidSdJwt", CredentialRequestParameters.configurationIdOf(subject))
    }

    /** Draft offers (EBSI, EWC) predate `proofs`. */
    @Test
    fun `a draft offer gets the singular proof`() {
        assertSingular(body(CredentialSubject.LegacyFormat(format = "jwt_vc"), session(offerVersion = 1)))
    }

    /**
     * Discovery records the metadata revision on the configuration. A draft 12 object-shaped
     * `credentials_supported` is indistinguishable from 1.0 after parsing, so this is the marker
     * that catches it; the array check below covers configurations stored before the field existed.
     */
    @Test
    fun `draft metadata gets the singular proof`() {
        val recorded = session().apply { issuerConfig?.version = 1 }
        assertSingular(body(CredentialSubject.LegacyFormat(format = "jwt_vc"), recorded))

        val arrayShaped = session(credentialsSupported = listOf(mapOf("format" to "jwt_vc")))
        assertSingular(body(CredentialSubject.LegacyFormat(format = "jwt_vc"), arrayShaped))
    }

    /**
     * A policy that forbids the plural form cannot carry a batch. Dropping to the first proof
     * would issue one credential of the several asked for and report success.
     */
    @Test(expected = CredentialRequestException.Unusable::class)
    fun `the legacy policy refuses a batch instead of sending one proof of many`() {
        body(
            CredentialSubject.ByConfiguration("PidSdJwt"),
            policy = CredentialRequestPolicy.Legacy,
            proofs = CredentialProofs.Jwt(listOf("proof.one", "proof.two")),
        )
    }

    /**
     * Draft 13 hands out `c_nonce` with the token and has no nonce endpoint. 1.0 removed `c_nonce`
     * from the token response, so an issuer that also publishes a nonce endpoint is not a draft.
     */
    @Test
    fun `a token c_nonce marks a draft only when there is no nonce endpoint`() {
        val token = TokenResponse(cNonce = "token-nonce")

        assertSingular(body(CredentialSubject.ByConfiguration("PidSdJwt"), token = token))
        assertPlural(
            body(
                CredentialSubject.ByConfiguration("PidSdJwt"),
                session(nonceEndpoint = "https://issuer.example.com/nonce"),
                token = token,
            ),
        )
    }

    /** A batch can only be expressed in the plural form, so it overrides the draft rule. */
    @Test
    fun `a batch to a draft issuer still takes the plural form`() {
        val body = body(
            CredentialSubject.LegacyFormat(format = "jwt_vc"),
            session(offerVersion = 1),
            proofs = CredentialProofs.Jwt(listOf("proof.one", "proof.two")),
        )

        assertEquals(listOf("proof.one", "proof.two"), body.proofs?.jwt)
        assertNull(body.proof)
    }

    /** The plural form is an object keyed by proof type; `proof_type` is not a member of it. */
    @Test
    fun `the plural form serialises as proofs keyed by type`() {
        val declares = session(mapOf("proof_types_supported" to mapOf("jwt" to emptyMap<String, Any>())))

        val json = Gson().toJson(body(CredentialSubject.ByConfiguration("PidSdJwt"), declares))

        assertTrue(json.contains("""{"proofs":{"jwt":["the.proof.jwt"]}"""))
        // `proof_type` is a member of the singular form only; the plural object is keyed by type.
        assertFalse(json.contains("proof_type"))
    }

    /** An issuer that rejects the 1.0 shape can be stepped back to singular. */
    @Test
    fun `policy can force the singular proof`() {
        val declares = session(mapOf("proof_types_supported" to mapOf("jwt" to emptyMap<String, Any>())))

        val request = body(CredentialSubject.ByConfiguration("PidSdJwt"), declares, CredentialRequestPolicy.Legacy)

        assertNull(request.proofs)
        assertEquals("the.proof.jwt", request.proof?.jwt)
    }
    /**
     * The subject carries the offer entry rather than a position into a list held elsewhere.
     *
     * The previous API took an `index` alongside the offer -- two parameters that had to agree,
     * with nothing enforcing it. Position is the wrong identifier: what names a credential across
     * the offer, the token response's authorization_details and the issuer metadata is its
     * configuration id.
     */
    @Test
    fun `the subject names the credential rather than its position`() {
        val second = Credentials(types = arrayListOf("SecondCredential"))

        val subject = CredentialSubject.ByConfiguration("SecondCredential", offerCredential = second)

        assertEquals(second, subject.offerCredential)
        assertEquals("SecondCredential", CredentialRequestParameters.configurationIdOf(subject))
        // And with no entry supplied it is absent, not defaulted to the offer's first credential.
        assertNull(CredentialSubject.ByConfiguration("SecondCredential").offerCredential)
    }
}
