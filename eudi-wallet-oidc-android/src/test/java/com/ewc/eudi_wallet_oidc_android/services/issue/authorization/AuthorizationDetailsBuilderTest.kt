package com.ewc.eudi_wallet_oidc_android.services.issue.authorization

import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.Credentials
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.TrustFramework
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.details.AuthorizationDetailsBuilder
import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** OpenID4VCI 1.0 section 5.1.1, the `openid_credential` authorization details type. */
class AuthorizationDetailsBuilderTest {

    private val issuer = "https://issuer.example.com"

    private fun session(
        version: Int,
        credentials: List<Credentials>,
        authorizationServers: List<String>? = null,
    ) = IssuanceSession(
        credentialOffer = CredentialOffer(
            credentialIssuer = issuer,
            credentials = ArrayList(credentials),
            version = version,
        ),
        issuerConfig = IssuerWellKnownConfiguration(
            credentialIssuer = issuer,
            authorizationServers = authorizationServers?.let { ArrayList(it) },
        ),
        authConfig = null,
    )

    private fun build(session: IssuanceSession, format: String? = null, docType: String? = null) =
        JsonParser.parseString(
            AuthorizationDetailsBuilder().build(
                session, format, docType,
                types = session.credentialOffer?.credentials?.firstOrNull()?.types ?: arrayListOf(),
            )
        ).asJsonArray

    // MARK: - OpenID4VCI 1.0

    @Test
    fun `a 1_0 detail carries the type and the configuration id`() {
        val details = build(session(2, listOf(Credentials(types = arrayListOf("PidSdJwt")))))

        assertEquals(1, details.size())
        val first = details[0].asJsonObject
        assertEquals("openid_credential", first.get("type").asString)
        assertEquals("PidSdJwt", first.get("credential_configuration_id").asString)
    }

    /**
     * "If the Credential Issuer metadata contains an authorization_servers parameter, the
     * authorization detail's locations common data field MUST be set to the Credential Issuer
     * Identifier value." The 1.0 path never set `locations` at all before.
     */
    @Test
    fun `locations is set when the issuer declares authorization servers`() {
        val details = build(
            session(
                2,
                listOf(Credentials(types = arrayListOf("PidSdJwt"))),
                authorizationServers = listOf("https://as.example.com"),
            )
        )
        val locations = details[0].asJsonObject.getAsJsonArray("locations")
        assertEquals(1, locations.size())
        assertEquals(issuer, locations[0].asString)
    }

    /** An issuer that is its own authorization server keeps the leaner request. */
    @Test
    fun `locations is omitted when no authorization servers are declared`() {
        val details = build(session(2, listOf(Credentials(types = arrayListOf("PidSdJwt")))))
        assertFalse(details[0].asJsonObject.has("locations"))
    }

    @Test
    fun `a 1_0 detail carries neither format nor doctype`() {
        val details = build(
            session(2, listOf(Credentials(types = arrayListOf("PidSdJwt")))),
            format = "dc+sd-jwt",
        )
        val first = details[0].asJsonObject
        assertFalse("1.0 carries the format in the credential configuration", first.has("format"))
        assertFalse(first.has("doctype"))
    }

    @Test
    fun `one detail per offered credential`() {
        val details = build(
            session(2, listOf(
                Credentials(types = arrayListOf("PidSdJwt")),
                Credentials(types = arrayListOf("MdlMdoc")),
            ))
        )
        assertEquals(2, details.size())
        assertEquals("MdlMdoc", details[1].asJsonObject.get("credential_configuration_id").asString)
    }

    // MARK: - Drafts

    /** The whole type hierarchy belongs to one credential and is carried intact. */
    @Test
    fun `an EBSI draft carries the full types array`() {
        val types = arrayListOf("VerifiableCredential", "VerifiableAttestation", "Diploma")
        val details = build(
            session(1, listOf(Credentials(types = types, trustFramework = TrustFramework(name = "ebsi")))),
            format = "jwt_vc",
        )
        val first = details[0].asJsonObject
        assertEquals(3, first.getAsJsonArray("types").size())
        assertEquals("Diploma", first.getAsJsonArray("types")[2].asString)
        assertTrue(first.has("locations"))
    }

    /** No trust framework means the EWC flavour, which uses credential_definition instead. */
    @Test
    fun `an EWC draft uses credential_definition`() {
        val details = build(
            session(1, listOf(Credentials(types = arrayListOf("VerifiableCredential", "Diploma")))),
            format = "jwt_vc",
        )
        val first = details[0].asJsonObject
        assertFalse(first.has("types"))
        assertEquals(2, first.getAsJsonObject("credential_definition").getAsJsonArray("type").size())
    }

    @Test
    fun `an mdoc draft carries the doctype`() {
        val details = build(
            session(1, listOf(Credentials(types = arrayListOf("org.iso.18013.5.1.mDL")))),
            format = "mso_mdoc",
            docType = "org.iso.18013.5.1.mDL",
        )
        val first = details[0].asJsonObject
        assertEquals("org.iso.18013.5.1.mDL", first.get("doctype").asString)
        assertEquals("mso_mdoc", first.get("format").asString)
    }
}
