package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata

import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.services.discovery.metadata.validator.IssuerMetadataValidator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/** OpenID4VCI 1.0 section 12.2.4, applied only to the revision that defines each rule. */
class IssuerMetadataValidatorTest {

    private val validator = IssuerMetadataValidator()
    private val identifier = "https://issuer.example.com"

    private fun config(
        credentialIssuer: String? = identifier,
        credentialEndpoint: String? = "https://issuer.example.com/credential",
        servers: List<String>? = null,
    ) = IssuerWellKnownConfiguration(
        credentialIssuer = credentialIssuer,
        credentialEndpoint = credentialEndpoint,
        authorizationServers = servers?.let { ArrayList(it) },
    )

    /** Most rules apply regardless of the identity check, which is off by default. */
    private fun validate(
        config: IssuerWellKnownConfiguration,
        version: IssuerMetadataSpecVersion = IssuerMetadataSpecVersion.V1_0,
        policy: DiscoveryPolicy = DiscoveryPolicy.Default,
    ) = validator.validate(config, version, identifier, policy)

    private val enforcing = DiscoveryPolicy.Default.copy(requireIssuerIdentifierMatch = true)

    @Test
    fun `a conformant document passes`() {
        val result = validate(config())
        assertEquals(identifier, result.credentialIssuer)
    }

    /** "If these values are not identical ... the data contained in the response MUST NOT be used." */
    @Test
    fun `a credential_issuer naming a different issuer is rejected when the check is enabled`() {
        val error = assertThrows(DiscoveryException.Invalid::class.java) {
            validate(config(credentialIssuer = "https://attacker.example.com"), policy = enforcing)
        }
        assertEquals(true, error.message?.contains("different issuer"))
    }

    /**
     * The default tolerates it. Deployed issuers publish one canonical identifier while answering
     * at other paths -- the iGrant issuers serve at `<base>/service` and declare
     * `<base>/service/version-01` -- so enforcing this by default rejects a working issuer.
     */
    @Test
    fun `a mismatched credential_issuer is tolerated by default`() {
        val result = validate(config(credentialIssuer = "$identifier/version-01"))
        assertEquals("$identifier/version-01", result.credentialIssuer)
    }

    /**
     * A trailing slash is tolerated in both revisions: the SDK strips one when deriving the
     * identifier, so an exact comparison would reject an issuer for our own normalisation. It is
     * the only difference tolerated -- a different host or path is still refused.
     */
    @Test
    fun `a trailing slash does not fail the identity check`() {
        validate(config(credentialIssuer = "$identifier/"), policy = enforcing)
        validate(config(credentialIssuer = "$identifier/"), version = IssuerMetadataSpecVersion.Draft, policy = enforcing)
    }

    @Test
    fun `a different path on the same host is still rejected when enforcing`() {
        assertThrows(DiscoveryException.Invalid::class.java) {
            validate(config(credentialIssuer = "$identifier/other"), policy = enforcing)
        }
    }

    @Test
    fun `a missing credential_issuer is rejected for 1_0 and adopted for drafts`() {
        assertThrows(DiscoveryException.Invalid::class.java) {
            validate(config(credentialIssuer = null))
        }
        val draft = validate(config(credentialIssuer = null), version = IssuerMetadataSpecVersion.Draft)
        assertEquals(identifier, draft.credentialIssuer)
    }

    @Test
    fun `a missing credential_endpoint is rejected for 1_0 and allowed for drafts`() {
        assertThrows(DiscoveryException.Invalid::class.java) {
            validate(config(credentialEndpoint = null))
        }
        validate(config(credentialEndpoint = null), version = IssuerMetadataSpecVersion.Draft)
    }

    @Test
    fun `a credential_endpoint on a disallowed scheme is rejected`() {
        val error = assertThrows(DiscoveryException.Invalid::class.java) {
            validate(config(credentialEndpoint = "file:///etc/passwd"))
        }
        assertEquals(true, error.message?.contains("unsupported scheme"))
    }

    @Test
    fun `an http credential_endpoint passes by default and fails under strict`() {
        validate(config(credentialEndpoint = "http://localhost:8080/credential"))
        assertThrows(DiscoveryException.Invalid::class.java) {
            validate(
                config(credentialEndpoint = "http://localhost:8080/credential"),
                policy = DiscoveryPolicy.Strict,
            )
        }
    }

    /** Section 12.2.4 calls it "a non-empty array"; empty and absent mean different things. */
    @Test
    fun `an empty authorization_servers array is rejected`() {
        assertThrows(DiscoveryException.Invalid::class.java) { validate(config(servers = emptyList())) }
        assertThrows(DiscoveryException.Invalid::class.java) { validate(config(servers = listOf("  "))) }
    }

    @Test
    fun `an absent authorization_servers array is fine`() {
        validate(config(servers = null))
    }
}
