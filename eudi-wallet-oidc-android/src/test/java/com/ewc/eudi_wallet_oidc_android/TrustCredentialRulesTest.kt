package com.ewc.eudi_wallet_oidc_android

import com.ewc.eudi_wallet_oidc_android.models.TrustCredentialType
import com.ewc.eudi_wallet_oidc_android.models.TrustListLookupResponse
import com.ewc.eudi_wallet_oidc_android.services.trust.TrustCredentialDecision
import com.ewc.eudi_wallet_oidc_android.services.trust.TrustCredentialDescriptor
import com.ewc.eudi_wallet_oidc_android.services.trust.TrustCredentialRules
import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `permittedCredentials` is an allow-list (non-empty ⇒ only those types), `prohibitedCredentials`
 * a deny-list. Both are per service, and both arrive as lists of {format, vct|doctype}.
 */
class TrustCredentialRulesTest {

    private val pidSdJwt = TrustCredentialType(format = "dc+sd-jwt", vct = "urn:eudi:pid:1")
    private val pidMdoc = TrustCredentialType(format = "mso_mdoc", doctype = "eu.europa.ec.eudi.pid.1")
    private val wua = TrustCredentialType(format = "dc+sd-jwt", vct = "WalletUnitAttestation")
    private val prohibited = listOf(pidSdJwt, pidMdoc, wua)

    @Test
    fun `no rules means allowed`() {
        val decision = TrustCredentialRules.evaluate(
            TrustCredentialDescriptor(format = "dc+sd-jwt", vct = "anything"),
            permitted = emptyList(), prohibited = emptyList()
        )
        assertEquals(TrustCredentialDecision.Allowed, decision)
    }

    @Test
    fun `prohibited vct is refused`() {
        val decision = TrustCredentialRules.evaluate(
            TrustCredentialDescriptor(format = "dc+sd-jwt", vct = "urn:eudi:pid:1"),
            permitted = emptyList(), prohibited = prohibited
        )
        assertTrue(decision is TrustCredentialDecision.Prohibited)
        assertEquals(pidSdJwt, (decision as TrustCredentialDecision.Prohibited).rule)
    }

    @Test
    fun `prohibited doctype is refused`() {
        val decision = TrustCredentialRules.evaluate(
            TrustCredentialDescriptor(format = "mso_mdoc", doctype = "eu.europa.ec.eudi.pid.1"),
            permitted = emptyList(), prohibited = prohibited
        )
        assertTrue(decision is TrustCredentialDecision.Prohibited)
    }

    @Test
    fun `the old vc+sd-jwt format name still matches a dc+sd-jwt rule`() {
        // Otherwise a PID prohibition silently fails on credentials labelled the old way.
        val decision = TrustCredentialRules.evaluate(
            TrustCredentialDescriptor(format = "vc+sd-jwt", vct = "urn:eudi:pid:1"),
            permitted = emptyList(), prohibited = prohibited
        )
        assertTrue(decision is TrustCredentialDecision.Prohibited)
    }

    @Test
    fun `a non-prohibited credential passes`() {
        val decision = TrustCredentialRules.evaluate(
            TrustCredentialDescriptor(format = "dc+sd-jwt", vct = "urn:eudi:diploma:1"),
            permitted = emptyList(), prohibited = prohibited
        )
        assertEquals(TrustCredentialDecision.Allowed, decision)
    }

    @Test
    fun `same vct in a different format is not prohibited`() {
        val decision = TrustCredentialRules.evaluate(
            TrustCredentialDescriptor(format = "mso_mdoc", doctype = "urn:eudi:pid:1"),
            permitted = emptyList(), prohibited = listOf(pidSdJwt)
        )
        assertEquals(TrustCredentialDecision.Allowed, decision)
    }

    @Test
    fun `permitted acts as an allow-list`() {
        val permitted = listOf(TrustCredentialType(format = "dc+sd-jwt", vct = "urn:eudi:diploma:1"))

        val allowed = TrustCredentialRules.evaluate(
            TrustCredentialDescriptor(format = "dc+sd-jwt", vct = "urn:eudi:diploma:1"),
            permitted = permitted, prohibited = emptyList()
        )
        assertEquals(TrustCredentialDecision.Allowed, allowed)

        val refused = TrustCredentialRules.evaluate(
            TrustCredentialDescriptor(format = "dc+sd-jwt", vct = "urn:eudi:pid:1"),
            permitted = permitted, prohibited = emptyList()
        )
        assertTrue(refused is TrustCredentialDecision.NotPermitted)
    }

    @Test
    fun `prohibited wins over permitted`() {
        val type = TrustCredentialType(format = "dc+sd-jwt", vct = "urn:eudi:pid:1")
        val decision = TrustCredentialRules.evaluate(
            TrustCredentialDescriptor(format = "dc+sd-jwt", vct = "urn:eudi:pid:1"),
            permitted = listOf(type), prohibited = listOf(type)
        )
        assertTrue(decision is TrustCredentialDecision.Prohibited)
    }

    @Test
    fun `format-only rule matches every credential of that format`() {
        val decision = TrustCredentialRules.evaluate(
            TrustCredentialDescriptor(format = "mso_mdoc", doctype = "anything.at.all"),
            permitted = emptyList(), prohibited = listOf(TrustCredentialType(format = "mso_mdoc"))
        )
        assertTrue(decision is TrustCredentialDecision.Prohibited)
    }

    @Test
    fun `unidentifiable credential skips the rules and says so`() {
        val decision = TrustCredentialRules.evaluate(
            null, permitted = emptyList(), prohibited = prohibited
        )
        assertEquals(TrustCredentialDecision.NotEvaluated, decision)
    }

    @Test
    fun `lists parse from the live response shape`() {
        val json = """
        {"match": true, "entries": [{
          "status": "granted",
          "service": {
            "serviceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance",
            "serviceStatus": "http://uri.etsi.org/19602/WRPACProvidersList/SvcStatus/notified"
          },
          "permittedCredentials": [],
          "prohibitedCredentials": [
            {"format": "dc+sd-jwt", "vct": "urn:eudi:pid:1"},
            {"format": "mso_mdoc", "doctype": "eu.europa.ec.eudi.pid.1"},
            {"format": "dc+sd-jwt", "vct": "WalletUnitAttestation"}
          ]
        }]}
        """.trimIndent()

        val entry = Gson().fromJson(json, TrustListLookupResponse::class.java).matchedEntries.first()

        assertTrue(entry.permittedCredentials.isEmpty())
        assertEquals(3, entry.prohibitedCredentials.size)
        assertEquals("urn:eudi:pid:1", entry.prohibitedCredentials[0].vct)
        assertEquals("eu.europa.ec.eudi.pid.1", entry.prohibitedCredentials[1].doctype)
    }

    @Test
    fun `the old object shape degrades to no rules instead of failing the response`() {
        val json = """
        {"match": true, "entries": [{
          "status": "granted",
          "service": {"serviceTypeIdentifier": "x"},
          "permittedCredentials": {"category": "QEAA", "issuesCredentials": true}
        }]}
        """.trimIndent()

        val response = Gson().fromJson(json, TrustListLookupResponse::class.java)

        assertEquals(1, response.grantedEntries.size)
        assertTrue(response.matchedEntries.first().permittedCredentials.isEmpty())
    }
}
