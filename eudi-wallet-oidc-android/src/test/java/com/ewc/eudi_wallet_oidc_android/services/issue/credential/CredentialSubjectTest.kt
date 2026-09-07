package com.ewc.eudi_wallet_oidc_android.services.issue.credential

import com.ewc.eudi_wallet_oidc_android.models.AuthorizationDetail
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.Credentials
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.TokenResponse
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Section 8.2's rule for which form names the credential.
 *
 * It lives in the SDK because it is the specification's rule, not a caller's preference -- the
 * wallet and the sample app would otherwise each have their own version of it, which is how the
 * four-branch chain this replaces came about.
 */
class CredentialSubjectTest {

    private val credential = Credentials(types = arrayListOf("PidSdJwt"))

    private fun session(nonceEndpoint: String? = "https://issuer.example.com/nonce") = IssuanceSession(
        credentialOffer = CredentialOffer(
            credentialIssuer = "https://issuer.example.com",
            credentials = arrayListOf(credential),
            version = 2,
        ),
        issuerConfig = IssuerWellKnownConfiguration(
            credentialIssuer = "https://issuer.example.com",
            nonceEndpoint = nonceEndpoint,
            credentialsSupported = mapOf("PidSdJwt" to mapOf("format" to "vc+sd-jwt")),
        ),
        authConfig = null,
    )

    private fun token(detail: AuthorizationDetail? = null) = TokenResponse(
        accessToken = "at-1",
        authorizationDetails = detail?.let { listOf(it) },
    )

    /** "REQUIRED when an Authorization Details of type `openid_credential` was returned." */
    @Test
    fun `credential_identifiers from the token response wins`() {
        val detail = AuthorizationDetail(
            type = "openid_credential",
            credentialConfigurationId = "PidSdJwt",
            credentialIdentifiers = listOf("identifier-1"),
        )

        val subject = CredentialSubject.of(session(), token(detail), credential)

        assertTrue(subject is CredentialSubject.ByIdentifier)
        assertEquals("identifier-1", (subject as CredentialSubject.ByIdentifier).credentialIdentifier)
        // And the offer entry travels with it, so the proof needs no lookup.
        assertEquals(credential, subject.offerCredential)
    }

    /** "REQUIRED if a `credential_identifiers` parameter was not returned from the Token Response." */
    @Test
    fun `the configuration id is used when no identifiers came back`() {
        val detail = AuthorizationDetail(type = "openid_credential", credentialConfigurationId = "PidSdJwt")

        val subject = CredentialSubject.of(session(), token(detail), credential)

        assertEquals("PidSdJwt", (subject as CredentialSubject.ByConfiguration).credentialConfigurationId)
    }

    /** With no authorization details at all, the offer names the configuration. */
    @Test
    fun `the offer names the configuration when the token said nothing`() {
        val subject = CredentialSubject.of(session(), token(), credential)

        assertEquals("PidSdJwt", (subject as CredentialSubject.ByConfiguration).credentialConfigurationId)
    }

    /**
     * No nonce endpoint means a pre-1.0 issuer, which names the credential by format. That proxy is
     * deliberate -- see the factory's own note about issuers that publish both.
     */
    @Test
    fun `an issuer with no nonce endpoint gets the draft shape`() {
        val subject = CredentialSubject.of(session(nonceEndpoint = null), token(), credential)

        assertTrue(subject is CredentialSubject.LegacyFormat)
        assertEquals("vc+sd-jwt", (subject as CredentialSubject.LegacyFormat).format)
    }

    /** mdoc names itself by doctype, whatever the metadata shape. */
    @Test
    fun `mdoc uses its doctype`() {
        val mdoc = Credentials(types = arrayListOf("org.iso.18013.5.1.mDL"), doctype = "org.iso.18013.5.1.mDL")
        val session = IssuanceSession(
            credentialOffer = CredentialOffer(credentials = arrayListOf(mdoc), version = 2),
            issuerConfig = IssuerWellKnownConfiguration(
                credentialsSupported = mapOf("org.iso.18013.5.1.mDL" to mapOf("format" to "mso_mdoc")),
            ),
            authConfig = null,
        )

        val subject = CredentialSubject.of(session, token(), mdoc)

        assertEquals("mso_mdoc", (subject as CredentialSubject.LegacyFormat).format)
        assertEquals("org.iso.18013.5.1.mDL", subject.docType)
    }
    /**
     * With several authorization details, a credential that matches none must **not** borrow the
     * first one's identifier.
     *
     * That is a request naming a different credential, and only the entries after the first are
     * affected — so it presents as one bad credential rather than a bad rule.
     */
    @Test
    fun `a credential that matches no authorization detail does not borrow another's identifier`() {
        val other = Credentials(types = arrayListOf("OtherCredential"))
        val token = TokenResponse(
            accessToken = "at-1",
            authorizationDetails = listOf(
                AuthorizationDetail(
                    type = "openid_credential",
                    credentialConfigurationId = "OtherCredential",
                    credentialIdentifiers = listOf("identifier-for-other"),
                ),
                AuthorizationDetail(
                    type = "openid_credential",
                    credentialConfigurationId = "ThirdCredential",
                    credentialIdentifiers = listOf("identifier-for-third"),
                ),
            ),
        )

        val subject = CredentialSubject.of(session(), token, credential)

        assertTrue("borrowed: $subject", subject is CredentialSubject.ByConfiguration)
        assertEquals("PidSdJwt", (subject as CredentialSubject.ByConfiguration).credentialConfigurationId)
    }

    /** One detail is unambiguous — that is the single-credential offer, and it still applies. */
    @Test
    fun `a sole authorization detail applies even without an exact match`() {
        val token = TokenResponse(
            accessToken = "at-1",
            authorizationDetails = listOf(
                AuthorizationDetail(
                    type = "openid_credential",
                    credentialConfigurationId = "SomethingElse",
                    credentialIdentifiers = listOf("identifier-1"),
                ),
            ),
        )

        val subject = CredentialSubject.of(session(), token, credential)

        assertEquals("identifier-1", (subject as CredentialSubject.ByIdentifier).credentialIdentifier)
    }
}
