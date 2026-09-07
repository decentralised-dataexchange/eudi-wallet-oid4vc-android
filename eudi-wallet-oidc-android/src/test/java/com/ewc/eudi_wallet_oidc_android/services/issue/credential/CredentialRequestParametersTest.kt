package com.ewc.eudi_wallet_oidc_android.services.issue.credential

import com.ewc.eudi_wallet_oidc_android.models.Credentials
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The credential request body: what each subject puts on the wire, and what it must not. */
class CredentialRequestParametersTest {

    private fun session(configuration: Map<String, Any> = emptyMap()) = IssuanceSession(
        credentialOffer = null,
        issuerConfig = IssuerWellKnownConfiguration(
            credentialIssuer = "https://issuer.example.com",
            credentialsSupported = mapOf("PidSdJwt" to configuration),
        ),
        authConfig = null,
    )

    private fun body(
        subject: CredentialSubject,
        session: IssuanceSession = session(),
        policy: CredentialRequestPolicy = CredentialRequestPolicy.Default,
    ) = CredentialRequestParameters.build(
        subject = subject,
        proof = "the.proof.jwt",
        session = session,
        encryption = null,
        policy = policy,
    )

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
     * Section 8.2: "The `proofs` parameter MUST be present if the `proof_types_supported` parameter
     * is present in the `credential_configurations_supported` parameter of the Issuer metadata."
     */
    @Test
    fun `plural proofs follow proof_types_supported, not credential_metadata`() {
        val declares = session(mapOf("proof_types_supported" to mapOf("jwt" to emptyMap<String, Any>())))
        val plural = body(CredentialSubject.ByConfiguration("PidSdJwt"), declares)
        assertEquals(listOf("the.proof.jwt"), plural.proofs?.jwt)
        assertNull(plural.proof)

        // The trigger both SDKs used to key off. On its own it must now change nothing.
        val onlyMetadata = session(mapOf("credential_metadata" to mapOf("x" to 1)))
        val singular = body(CredentialSubject.ByConfiguration("PidSdJwt"), onlyMetadata)
        assertEquals("the.proof.jwt", singular.proof?.jwt)
        assertEquals("jwt", singular.proof?.proofType)
        assertNull(singular.proofs)
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
