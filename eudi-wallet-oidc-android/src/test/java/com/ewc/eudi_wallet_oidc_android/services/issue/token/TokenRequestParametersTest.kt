package com.ewc.eudi_wallet_oidc_android.services.issue.token

import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.Grants
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.ewc.eudi_wallet_oidc_android.models.PreAuthorizationCode
import com.ewc.eudi_wallet_oidc_android.models.TxCode
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.IssuanceSession
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The token request body: what goes on the wire for each grant, and what is left off. */
class TokenRequestParametersTest {

    private fun session(
        version: Int? = 2,
        txCode: TxCode? = null,
        preAuthorized: Boolean = true,
        authorizationServers: ArrayList<String>? = null,
    ) = IssuanceSession(
        credentialOffer = CredentialOffer(
            credentialIssuer = "https://issuer.example.com",
            version = version,
            grants = if (preAuthorized) {
                Grants(preAuthorizationCode = PreAuthorizationCode(preAuthorizedCode = "pre-1", transactionCode = txCode))
            } else null,
        ),
        issuerConfig = IssuerWellKnownConfiguration(
            credentialIssuer = "https://issuer.example.com",
            authorizationServers = authorizationServers,
        ),
        authConfig = null,
    )

    private fun build(
        session: IssuanceSession,
        grant: TokenGrant,
        policy: TokenRequestPolicy = TokenRequestPolicy.Default,
    ) = TokenRequestParameters.build(
        session = session,
        wallet = WalletIdentity("did:key:zabc", null),
        attestation = null,
        grant = grant,
        authorizationDetails = "[{\"type\":\"openid_credential\"}]",
        policy = policy,
    ).toMap()

    @Test
    fun `the pre-authorized grant names the code as pre-authorized_code`() {
        val body = build(session(), TokenGrant.PreAuthorized("pre-1"))

        assertEquals("urn:ietf:params:oauth:grant-type:pre-authorized_code", body["grant_type"])
        assertEquals("pre-1", body["pre-authorized_code"])
        assertNull(body["code"])
        // Section 6.1: client authentication is OPTIONAL for this grant, and none is sent.
        assertNull(body["client_id"])
    }

    @Test
    fun `the authorization code grant sends the code, verifier and redirect`() {
        val body = build(
            session(preAuthorized = false),
            TokenGrant.AuthorizationCode("abc", "verifier", "datawallet://callback"),
        )

        assertEquals("authorization_code", body["grant_type"])
        assertEquals("abc", body["code"])
        assertEquals("verifier", body["code_verifier"])
        assertEquals("datawallet://callback", body["redirect_uri"])
        assertNull(body["pre-authorized_code"])
    }

    /** The old implementation sent `code_verifier=` and `redirect_uri=` rather than omitting them. */
    @Test
    fun `blank values are omitted rather than sent empty`() {
        val body = build(
            session(preAuthorized = false),
            TokenGrant.AuthorizationCode("abc", codeVerifier = null, redirectUri = null),
        )

        assertFalse(body.containsKey("code_verifier"))
        assertFalse(body.containsKey("redirect_uri"))
    }

    /** 1.0 calls it `tx_code`; the pre-1.0 drafts called it `user_pin`. */
    @Test
    fun `the transaction code parameter is named for the offer's revision`() {
        val v1 = build(session(version = 1), TokenGrant.PreAuthorized("pre-1", txCode = "1234"))
        assertEquals("1234", v1["user_pin"])
        assertNull(v1["tx_code"])

        val v2 = build(session(version = 2), TokenGrant.PreAuthorized("pre-1", txCode = "1234"))
        assertEquals("1234", v2["tx_code"])
        assertNull(v2["user_pin"])
    }

    /**
     * Section 6.1: the code "MUST be present if a `tx_code` object was present in the Credential
     * Offer (**including if the object was empty**)". The old implementation asked whether a PIN
     * had been passed, which is a different question.
     */
    @Test
    fun `an empty tx_code object still obliges the wallet to send one`() {
        assertTrue(session(txCode = TxCode()).requiresTransactionCode)
        assertTrue(session(txCode = TxCode(length = 4, inputMode = "numeric")).requiresTransactionCode)
        assertFalse(session(txCode = null).requiresTransactionCode)
    }

    /** Sections 5.1.2 and 6.1 attach `resource` to the plural `authorization_servers`. */
    @Test
    fun `resource is sent only under policy and only when authorization_servers is declared`() {
        val strict = TokenRequestPolicy.Strict

        val declared = build(
            session(authorizationServers = arrayListOf("https://as.example.com")),
            TokenGrant.PreAuthorized("pre-1"),
            strict,
        )
        assertEquals("https://issuer.example.com", declared["resource"])

        val notDeclared = build(session(), TokenGrant.PreAuthorized("pre-1"), strict)
        assertNull(notDeclared["resource"])

        // Off by default: the token endpoint has no "ignore unknown parameters" rule, and RFC 8707
        // lets a server reject an unknown target.
        val byDefault = build(
            session(authorizationServers = arrayListOf("https://as.example.com")),
            TokenGrant.PreAuthorized("pre-1"),
        )
        assertNull(byDefault["resource"])
        assertNull(byDefault["authorization_details"])
    }
}
