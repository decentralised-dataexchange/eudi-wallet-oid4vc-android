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
     * Section 12.2.4: a 1.0 issuer that requires no `c_nonce` publishes no nonce endpoint. That
     * absence is not a draft marker, so the request still names the credential the 1.0 way (N3).
     */
    @Test
    fun `a 1_0 issuer with no nonce endpoint still gets credential_configuration_id`() {
        val subject = CredentialSubject.of(session(nonceEndpoint = null), token(), credential)

        assertEquals("PidSdJwt", (subject as CredentialSubject.ByConfiguration).credentialConfigurationId)
    }

    /** The offer parser recorded a draft shape (EBSI, EWC). */
    @Test
    fun `a draft offer gets the draft shape`() {
        val draftOffer = session().copy(
            credentialOffer = CredentialOffer(credentials = arrayListOf(credential), version = 1),
        )

        val subject = CredentialSubject.of(draftOffer, token(), credential)

        assertEquals("vc+sd-jwt", (subject as CredentialSubject.LegacyFormat).format)
    }

    /** Discovery recorded draft `credentials_supported` metadata, even with a 1.0-shaped offer. */
    @Test
    fun `draft metadata gets the draft shape`() {
        val draftMetadata = session(nonceEndpoint = null).apply { issuerConfig?.version = 1 }

        val subject = CredentialSubject.of(draftMetadata, token(), credential)

        assertTrue("got $subject", subject is CredentialSubject.LegacyFormat)
    }

    /** Drafts 13 and 14 hand the nonce out with the token; 1.0 moved it to the nonce endpoint. */
    @Test
    fun `a token c_nonce without a nonce endpoint gets the draft shape`() {
        val draftToken = TokenResponse(accessToken = "at-1", cNonce = "nonce-1")

        val subject = CredentialSubject.of(session(nonceEndpoint = null), draftToken, credential)

        assertTrue("got $subject", subject is CredentialSubject.LegacyFormat)
        // The same c_nonce next to a nonce endpoint is a 1.0 issuer that also sends one.
        val both = CredentialSubject.of(session(), draftToken, credential)
        assertTrue("got $both", both is CredentialSubject.ByConfiguration)
    }

    /** A draft mdoc names itself by doctype, whatever the metadata shape. */
    @Test
    fun `mdoc uses its doctype`() {
        val mdoc = Credentials(types = arrayListOf("org.iso.18013.5.1.mDL"), doctype = "org.iso.18013.5.1.mDL")
        val session = IssuanceSession(
            credentialOffer = CredentialOffer(credentials = arrayListOf(mdoc), version = 1),
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
     * A draft offer may name an mdoc by its configuration id and leave the doctype to the
     * metadata. Sending the id as `doctype` asks for a document type that does not exist.
     */
    @Test
    fun `an mdoc named by configuration id takes its doctype from the metadata`() {
        val mdoc = Credentials(types = arrayListOf("MdlConfig"))
        val session = IssuanceSession(
            credentialOffer = CredentialOffer(credentials = arrayListOf(mdoc), version = 1),
            issuerConfig = IssuerWellKnownConfiguration(
                credentialsSupported = mapOf(
                    "MdlConfig" to mapOf("format" to "mso_mdoc", "doctype" to "org.iso.18013.5.1.mDL"),
                ),
            ),
            authConfig = null,
        )

        val subject = CredentialSubject.of(session, token(), mdoc) as CredentialSubject.LegacyFormat

        assertEquals("org.iso.18013.5.1.mDL", subject.docType)
    }

    /**
     * Map-shaped draft metadata that does not declare the offered type yields an empty type list
     * from the lookup. The offer's own types still name the credential, so they are sent rather
     * than refusing the request as naming nothing.
     */
    @Test
    fun `a type the draft metadata does not declare falls back to the offer's types`() {
        val undeclared = Credentials(types = arrayListOf("VerifiableCredential", "NotInMetadata"))
        val session = IssuanceSession(
            credentialOffer = CredentialOffer(credentials = arrayListOf(undeclared), version = 1),
            issuerConfig = IssuerWellKnownConfiguration(
                credentialsSupported = mapOf("PidSdJwt" to mapOf("format" to "jwt_vc")),
            ),
            authConfig = null,
        )

        val subject = CredentialSubject.of(session, token(), undeclared) as CredentialSubject.LegacyFormat

        assertEquals(listOf("VerifiableCredential", "NotInMetadata"), subject.credentialDefinitionTypes)
        assertTrue(!subject.namesNothing)
    }
    /**
     * With several authorization details, a credential that matches none must **not** borrow the
     * first one's identifier.
     *
     * That is a request naming a different credential, and only the entries after the first are
     * affected - so it presents as one bad credential rather than a bad rule.
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

    /**
     * A sole detail that names a *different* configuration is not borrowed either (N6): offer
     * [A, B], the token authorised A only, and B is being requested. Borrowing would issue A
     * twice and file the copy under B's name.
     */
    @Test
    fun `a sole authorization detail for another credential is not borrowed`() {
        val token = TokenResponse(
            accessToken = "at-1",
            authorizationDetails = listOf(
                AuthorizationDetail(
                    type = "openid_credential",
                    credentialConfigurationId = "SomethingElse",
                    credentialIdentifiers = listOf("identifier-for-something-else"),
                ),
            ),
        )

        val subject = CredentialSubject.of(session(), token, credential)

        assertEquals("PidSdJwt", (subject as CredentialSubject.ByConfiguration).credentialConfigurationId)
    }

    /** A sole detail that names no configuration cannot contradict the offer, so it applies. */
    @Test
    fun `a sole authorization detail without a configuration id applies`() {
        val detail = AuthorizationDetail(type = "openid_credential", credentialIdentifiers = listOf("identifier-1"))

        val subject = CredentialSubject.of(session(), token(detail), credential)

        assertEquals("identifier-1", (subject as CredentialSubject.ByIdentifier).credentialIdentifier)
    }

    /** With no offer entry to compare against (reissuance without an offer), a sole detail applies. */
    @Test
    fun `a sole authorization detail applies when there is no offer entry`() {
        val detail = AuthorizationDetail(
            type = "openid_credential",
            credentialConfigurationId = "SomethingElse",
            credentialIdentifiers = listOf("identifier-1"),
        )

        val subject = CredentialSubject.of(session(), token(detail), credential = null)

        assertEquals("identifier-1", (subject as CredentialSubject.ByIdentifier).credentialIdentifier)
    }
}
