package com.ewc.eudi_wallet_oidc_android.services.issue.offer

import com.ewc.eudi_wallet_oidc_android.services.issue.offer.parser.OpenId4VciV1OfferParser
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.parser.legacy.EbsiDraftOfferParser
import com.ewc.eudi_wallet_oidc_android.services.issue.offer.parser.legacy.EwcDraftOfferParser
import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Each parser recognises exactly one spec revision, by document shape alone.
 */
class CredentialOfferParserTest {

    private val v1_0 = OpenId4VciV1OfferParser()
    private val ebsiDraft = EbsiDraftOfferParser()
    private val ewcDraft = EwcDraftOfferParser()

    private fun json(raw: String) = JsonParser.parseString(raw).asJsonObject

    // ── OpenID4VCI 1.0 ──────────────────────────────────────────────────────

    @Test
    fun `1_0 is recognised by credential_configuration_ids`() {
        val offer = json(
            """{"credential_issuer":"https://issuer.example",
                "credential_configuration_ids":["PID","mDL"]}"""
        )
        assertTrue(v1_0.supports(offer))
        assertEquals(CredentialOfferSpecVersion.V1_0, v1_0.specVersion)
    }

    @Test
    fun `1_0 maps each configuration id to its own entry, in order`() {
        val parsed = v1_0.parse(
            json(
                """{"credential_issuer":"https://issuer.example",
                    "credential_configuration_ids":["PID","mDL"]}"""
            )
        )
        assertEquals("https://issuer.example", parsed.credentialIssuer)
        assertEquals(2, parsed.credentials?.size)
        assertEquals(listOf("PID"), parsed.credentials?.get(0)?.types?.toList())
        assertEquals(listOf("mDL"), parsed.credentials?.get(1)?.types?.toList())
    }

    @Test
    fun `1_0 carries the tx_code through`() {
        val parsed = v1_0.parse(
            json(
                """{"credential_issuer":"https://issuer.example",
                    "credential_configuration_ids":["PID"],
                    "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                      "pre-authorized_code":"PRE-1",
                      "tx_code":{"length":5,"input_mode":"text","description":"Check your email"}}}}"""
            )
        )
        val txCode = parsed.grants?.preAuthorizationCode?.transactionCode
        assertEquals(5, txCode?.length)
        assertEquals("text", txCode?.inputMode)
        assertEquals("Check your email", txCode?.description)
    }

    @Test
    fun `1_0 does not claim a draft offer`() {
        assertFalse(v1_0.supports(json("""{"credentials":["PID"]}""")))
        assertFalse(v1_0.supports(json("""{"credentials":[{"format":"jwt_vc","types":["A"]}]}""")))
        assertFalse(v1_0.supports(json("{}")))
    }

    // ── draft, EBSI flavour (credentials = objects) ──────────────────────────

    @Test
    fun `ebsi draft is recognised by an object array`() {
        val offer = json(
            """{"credential_issuer":"https://issuer.example",
                "credentials":[{"format":"jwt_vc_json","types":["VerifiableCredential","PID"]}]}"""
        )
        assertTrue(ebsiDraft.supports(offer))
        assertFalse(ewcDraft.supports(offer))
        assertEquals(CredentialOfferSpecVersion.Draft, ebsiDraft.specVersion)
    }

    @Test
    fun `ebsi draft preserves format and mdoc doctype`() {
        val parsed = ebsiDraft.parse(
            json(
                """{"credential_issuer":"https://issuer.example",
                    "credentials":[{"format":"mso_mdoc","doctype":"org.iso.18013.5.1.mDL"}]}"""
            )
        )
        val credential = parsed.credentials?.single()
        assertEquals("mso_mdoc", credential?.format)
        assertEquals("org.iso.18013.5.1.mDL", credential?.doctype)
    }

    @Test
    fun `a draft pin requirement yields a code prompt with no fabricated length`() {
        val parsed = ebsiDraft.parse(
            json(
                """{"credential_issuer":"https://issuer.example",
                    "credentials":[{"types":["PID"]}],
                    "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                      "pre-authorized_code":"PRE-1","user_pin_required":true}}}"""
            )
        )
        val txCode = parsed.grants?.preAuthorizationCode?.transactionCode
        // Non-null is what triggers the PIN screen...
        assertTrue(txCode != null)
        // ...but drafts never declare a length, so nothing may be invented.
        assertNull(txCode?.length)
    }

    @Test
    fun `no pin requirement means no code prompt`() {
        val parsed = ebsiDraft.parse(
            json(
                """{"credential_issuer":"https://issuer.example",
                    "credentials":[{"types":["PID"]}],
                    "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                      "pre-authorized_code":"PRE-1","user_pin_required":false}}}"""
            )
        )
        assertNull(parsed.grants?.preAuthorizationCode?.transactionCode)
    }

    // ── draft, EWC flavour (credentials = strings) ───────────────────────────

    @Test
    fun `ewc draft is recognised by a string array`() {
        val offer = json(
            """{"credential_issuer":"https://issuer.example","credentials":["PID"]}"""
        )
        assertTrue(ewcDraft.supports(offer))
        assertFalse(ebsiDraft.supports(offer))
    }

    @Test
    fun `ewc draft keeps the whole type chain`() {
        val parsed = ewcDraft.parse(
            json(
                """{"credential_issuer":"https://issuer.example",
                    "credentials":["VerifiableCredential","VerifiableAttestation","PortableDocumentA1"]}"""
            )
        )
        assertEquals(
            listOf("VerifiableCredential", "VerifiableAttestation", "PortableDocumentA1"),
            parsed.credentials?.single()?.types?.toList(),
        )
    }

    // ── the catch-all regression ────────────────────────────────────────────

    @Test
    fun `an empty object is claimed by no parser`() {
        // Previously the EWC draft path accepted this and produced an offer with nothing in it.
        val empty = json("{}")
        assertFalse(v1_0.supports(empty))
        assertFalse(ebsiDraft.supports(empty))
        assertFalse(ewcDraft.supports(empty))
    }

    @Test
    fun `a non-array credentials value is claimed by no parser`() {
        val offer = json("""{"credential_issuer":"https://x.example","credentials":"PID"}""")
        assertFalse(ebsiDraft.supports(offer))
        assertFalse(ewcDraft.supports(offer))
    }
}
