package com.ewc.eudi_wallet_oidc_android.services.verification.match

import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.models.Constraints
import com.ewc.eudi_wallet_oidc_android.models.Fields
import com.ewc.eudi_wallet_oidc_android.models.InputDescriptors
import com.ewc.eudi_wallet_oidc_android.models.PresentationDefinition
import com.ewc.eudi_wallet_oidc_android.services.verification.CertificateFixtures
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationService
import com.google.gson.Gson
import com.google.gson.JsonParser
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * One case per row of the leg 3 matrix in VERIFICATION_REVAMP_PLAN_ANDROID.md, over a small
 * wallet: a PID as SD-JWT VC, the same PID without holder binding, an mDL, and a W3C VC as a JWT.
 */
class DcqlCredentialMatcherTest {

    private val holder = VerificationFixtures.key("holder")
    private val cnf = mapOf("jwk" to holder.toPublicJWK().toJSONObject())

    private val pidClaims = mapOf(
        "vct" to VerificationFixtures.VCT,
        "iss" to "https://issuer.example",
        "given_name" to "Alice",
        "family_name" to "Doe",
        "age_over_18" to true,
        "nationalities" to listOf("SE", "DK"),
        "address" to mapOf("street_address" to "Main 1", "locality" to "Stockholm"),
    )
    private val pid = VerificationFixtures.signedJwt(pidClaims + ("cnf" to cnf)) + "~"
    private val pidWithoutBinding = VerificationFixtures.signedJwt(pidClaims) + "~"
    private val mdl = VerificationFixtures.mdoc(
        holder, VerificationFixtures.DOC_TYPE,
        mapOf("org.iso.18013.5.1" to mapOf("family_name" to "Doe", "given_name" to "Alice")),
    )
    private val degree = VerificationFixtures.signedJwt(mapOf(
        "vc" to mapOf(
            "type" to listOf("VerifiableCredential", "UniversityDegree"),
            "credentialSubject" to mapOf("degree" to "BSc"),
        ),
        "cnf" to cnf,
    ))
    private val wallet = listOf(pid, pidWithoutBinding, mdl, degree, null, "")

    private fun dcql(json: String): DCQL = Gson().fromJson(json, DCQL::class.java)

    private fun match(json: String, credentials: List<String?> = wallet): CredentialMatches =
        runBlocking { DcqlCredentialMatcher().match(PresentationQuery.Dcql(dcql(json)), credentials) }

    private fun pidQuery(extra: String = "", meta: String = """"meta":{"vct_values":["${VerificationFixtures.VCT}"]}""") =
        """{"credentials":[{"id":"pid","format":"dc+sd-jwt",$meta$extra}]}"""

    private fun claims(vararg paths: String) = paths.joinToString(",", prefix = ""","claims":[""", postfix = "]") { """{"path":[$it]}""" }

    // ── 3.1 to 3.5 ───────────────────────────────────────────────────────────

    @Test
    fun `3_1 a vct match with no claims is a candidate with nothing to disclose`() {
        val result = match(pidQuery())
        assertEquals(listOf(pid), result.candidatesFor("pid").map { it.credential })
        assertTrue(result.candidatesFor("pid").single().claims.isEmpty())
        assertTrue(result.satisfiable)
        assertEquals("pid", result.entries.single().entry.id)
    }

    @Test
    fun `3_2 a vct mismatch leaves the entry unsatisfied`() {
        val result = match(pidQuery(meta = """"meta":{"vct_values":["urn:other"]}"""))
        assertTrue(result.candidatesFor("pid").isEmpty())
        assertFalse(result.satisfiable)
        assertEquals(listOf("pid"), result.unsatisfied)
    }

    @Test
    fun `3_3 all requested claims present gives a candidate carrying those claims`() {
        val result = match(pidQuery(claims("\"given_name\"", "\"family_name\"")))
        val candidate = result.candidatesFor("pid").single()
        assertEquals(listOf(listOf("given_name"), listOf("family_name")), candidate.claims)
    }

    @Test
    fun `3_4 a missing claim without claim_sets excludes the credential`() {
        assertTrue(match(pidQuery(claims("\"given_name\"", "\"birthdate\""))).candidatesFor("pid").isEmpty())
    }

    @Test
    fun `3_5 a values restriction is honoured`() {
        assertTrue(match(pidQuery(""","claims":[{"path":["given_name"],"values":["Bob"]}]""")).candidatesFor("pid").isEmpty())
        assertEquals(1, match(pidQuery(""","claims":[{"path":["given_name"],"values":["Bob","Alice"]}]""")).candidatesFor("pid").size)
        assertEquals(1, match(pidQuery(""","claims":[{"path":["age_over_18"],"values":[true]}]""")).candidatesFor("pid").size)
    }

    // ── 3.6 claim sets ───────────────────────────────────────────────────────

    @Test
    fun `3_6 claim_sets select the first option the credential satisfies`() {
        val claims = ""","claims":[{"id":"a","path":["given_name"]},{"id":"b","path":["age_over_18"]},{"id":"c","path":["birthdate"]}]"""
        val second = match(pidQuery("""$claims,"claim_sets":[["c"],["a","b"]]"""))
        assertEquals(listOf(listOf("given_name"), listOf("age_over_18")), second.candidatesFor("pid").single().claims)

        assertTrue(match(pidQuery("""$claims,"claim_sets":[["c"]]""")).candidatesFor("pid").isEmpty())
        assertTrue(match(pidQuery("""$claims,"claim_sets":[["c","a"]]""")).candidatesFor("pid").isEmpty())
    }

    // ── 3.7 / 3.8 / 3.9 credential sets and multiple ────────────────────────

    private val twoQueries = """
        {"credentials":[
          {"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["${VerificationFixtures.VCT}"]}},
          {"id":"passport","format":"mso_mdoc","meta":{"doctype_value":"org.iso.23220.passport"}}
        ],"credential_sets":[
          {"options":[["pid"]]},
          {"options":[["passport"]],"required":%s,"purpose":"travel"}
        ]}
    """

    @Test
    fun `3_7 a required credential set nothing satisfies makes the request unsatisfiable`() {
        val result = match(twoQueries.format("true"))
        assertFalse(result.satisfiable)
        assertEquals(listOf("travel"), result.unsatisfied)
        assertEquals(1, result.candidatesFor("pid").size)
        assertTrue(result.entries.all { it.entry.required })
    }

    @Test
    fun `3_8 an optional credential set nothing satisfies leaves the request satisfiable`() {
        val result = match(twoQueries.format("false"))
        assertTrue(result.satisfiable)
        assertTrue(result.unsatisfied.isEmpty())
        assertFalse(result.entries.first { it.entry.id == "passport" }.entry.required)
        assertTrue(result.entries.first { it.entry.id == "pid" }.entry.required)
    }

    @Test
    fun `3_9 every matching credential is a candidate and multiple is carried on the entry`() {
        val secondPid = VerificationFixtures.signedJwt(pidClaims + ("given_name" to "Alicia") + ("cnf" to cnf)) + "~"
        val result = match(pidQuery(""","multiple":true"""), wallet + secondPid)
        assertEquals(listOf(pid, secondPid), result.candidatesFor("pid").map { it.credential })
        assertTrue(result.entries.single().entry.multiple)
        assertFalse(match(pidQuery()).entries.single().entry.multiple)
    }

    // ── 3.10 / 3.11 mdoc ─────────────────────────────────────────────────────

    private fun mdlQuery(claims: String = "") =
        """{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"${VerificationFixtures.DOC_TYPE}"}$claims}]}"""

    @Test
    fun `3_10 an mdoc matches by doctype and a namespace element path`() {
        assertEquals(listOf(mdl), match(mdlQuery()).candidatesFor("mdl").map { it.credential })
        val byPath = match(mdlQuery(""","claims":[{"path":["org.iso.18013.5.1","family_name"]}]""")).candidatesFor("mdl").single()
        assertEquals(listOf(listOf("org.iso.18013.5.1", "family_name")), byPath.claims)
        val legacy = match(mdlQuery(""","claims":[{"namespace":"org.iso.18013.5.1","claim_name":"given_name"}]""")).candidatesFor("mdl").single()
        assertEquals(listOf(listOf("org.iso.18013.5.1", "given_name")), legacy.claims)
    }

    @Test
    fun `3_11 an mdoc missing the element or with another doctype is excluded`() {
        assertTrue(match(mdlQuery(""","claims":[{"path":["org.iso.18013.5.1","portrait"]}]""")).candidatesFor("mdl").isEmpty())
        assertTrue(match("""{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.other"}}]}""").candidatesFor("mdl").isEmpty())
    }

    // ── 3.12 W3C VC ──────────────────────────────────────────────────────────

    @Test
    fun `3_12 a jwt_vc_json matches on type_values and subject claims`() {
        val ok = match("""{"credentials":[{"id":"deg","format":"jwt_vc_json","meta":{"type_values":[["UniversityDegree"]]},"claims":[{"path":["degree"]}]}]}""")
        assertEquals(listOf(degree), ok.candidatesFor("deg").map { it.credential })
        val wrongType = match("""{"credentials":[{"id":"deg","format":"jwt_vc_json","meta":{"type_values":[["Diploma"]]}}]}""")
        assertTrue(wrongType.candidatesFor("deg").isEmpty())
    }

    // ── 3.14 / 3.15 trusted authorities ──────────────────────────────────────

    private fun pidWithChain(): String {
        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .x509CertChain(listOf(Base64.encode(CertificateFixtures.verifierCert.encoded))).build()
        val builder = JWTClaimsSet.Builder()
        (pidClaims + ("cnf" to cnf)).forEach { (k, v) -> builder.claim(k, v) }
        return SignedJWT(header, builder.build()).apply { sign(ECDSASigner(CertificateFixtures.verifierKey)) }.serialize() + "~"
    }

    @Test
    fun `3_14 an aki trusted authority matches the issuer chain's AuthorityKeyIdentifier`() {
        val chained = pidWithChain()
        val aki = TrustedAuthorityMatcher.authorityKeyIdentifier(CertificateFixtures.verifierCert)!!
        val ok = match(pidQuery(""","trusted_authorities":[{"type":"aki","values":["$aki"]}]"""), listOf(chained, pid))
        assertEquals(listOf(chained), ok.candidatesFor("pid").map { it.credential })
        val other = TrustedAuthorityMatcher.authorityKeyIdentifier(CertificateFixtures.otherCert)!!
        assertTrue(match(pidQuery(""","trusted_authorities":[{"type":"aki","values":["$other"]}]"""), listOf(chained)).candidatesFor("pid").isEmpty())
    }

    @Test
    fun `3_15 an unknown trusted authority type matches nothing`() {
        assertTrue(match(pidQuery(""","trusted_authorities":[{"type":"openid_federation","values":["https://fed.example"]}]"""), listOf(pidWithChain())).candidatesFor("pid").isEmpty())
    }

    // ── 3.16 / 3.17 holder binding ───────────────────────────────────────────

    @Test
    fun `3_16 an SD-JWT without cnf is excluded by default`() {
        val result = match(pidQuery(), listOf(pidWithoutBinding))
        assertTrue(result.candidatesFor("pid").isEmpty())
        assertEquals(listOf(pid), match(pidQuery()).candidatesFor("pid").map { it.credential })
    }

    @Test
    fun `3_17 require_cryptographic_holder_binding false accepts it`() {
        val result = match(pidQuery(""","require_cryptographic_holder_binding":false"""), listOf(pidWithoutBinding))
        assertEquals(listOf(pidWithoutBinding), result.candidatesFor("pid").map { it.credential })
    }

    // ── 3.18 claims path pointers ────────────────────────────────────────────

    @Test
    fun `3_18 null selects every array element and an index selects one`() {
        assertEquals(1, match(pidQuery(claims("\"nationalities\", null"))).candidatesFor("pid").size)
        assertEquals(1, match(pidQuery(claims("\"nationalities\", 1"))).candidatesFor("pid").size)
        assertEquals(1, match(pidQuery(claims("\"address\", \"street_address\""))).candidatesFor("pid").size)
        assertTrue(match(pidQuery(claims("\"nationalities\", 5"))).candidatesFor("pid").isEmpty())
        assertTrue(match(pidQuery(claims("\"address\", null"))).candidatesFor("pid").isEmpty())
        assertEquals(1, match(pidQuery(""","claims":[{"path":["nationalities",null],"values":["DK"]}]""")).candidatesFor("pid").size)
    }

    @Test
    fun `claims path pointer processing follows section 7_1`() {
        val json = JsonParser.parseString("""{"a":{"b":[{"c":1},{"c":2}]},"s":"x"}""")
        assertEquals(listOf(1L, 2L), ClaimsPathPointer.selectValues(json, listOf("a", "b", null, "c")))
        assertEquals(listOf(2L), ClaimsPathPointer.selectValues(json, listOf("a", "b", "1", "c")))
        assertEquals(listOf("x"), ClaimsPathPointer.selectValues(json, listOf("s")))
        assertNull(ClaimsPathPointer.selectValues(json, listOf("s", "t")))
        assertNull(ClaimsPathPointer.selectValues(json, listOf("a", null)))
        assertNull(ClaimsPathPointer.selectValues(json, listOf("missing")))
        assertNull(ClaimsPathPointer.selectValues(json, emptyList()))
    }

    // ── 3.19 / 3.21 wallet shapes ────────────────────────────────────────────

    @Test
    fun `3_19 a mixed wallet matches each format independently`() {
        val result = match("""{"credentials":[
            {"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["${VerificationFixtures.VCT}"]}},
            {"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"${VerificationFixtures.DOC_TYPE}"}}]}""")
        assertEquals(listOf(pid), result.candidatesFor("pid").map { it.credential })
        assertEquals(listOf(mdl), result.candidatesFor("mdl").map { it.credential })
        assertTrue(result.satisfiable)
    }

    @Test
    fun `3_21 an empty wallet or an unknown format gives entries without candidates`() {
        val empty = match(pidQuery(), emptyList())
        assertEquals(1, empty.entries.size)
        assertFalse(empty.satisfiable)
        assertTrue(match("""{"credentials":[{"id":"x","format":"ldp_vc","meta":{}}]}""").candidatesFor("x").isEmpty())
    }

    // ── adapter and legacy ───────────────────────────────────────────────────

    @Test
    @Suppress("DEPRECATION")
    fun `the deprecated filterCredentials returns the candidates per entry in query order`() {
        val query = dcql(twoQueries.format("true"))
        val legacy = runBlocking { VerificationService().filterCredentials(wallet, query) }
        assertEquals(listOf(listOf(pid), emptyList()), legacy)
        assertTrue(runBlocking { VerificationService().filterCredentials(wallet, "not a query") }.isEmpty())
    }

    @Test
    fun `3_20 a presentation definition goes through the legacy matcher with one entry per descriptor`() {
        fun constrained(descriptor: InputDescriptors, path: String) = descriptor.copy(
            constraints = Constraints(fields = arrayListOf(Fields(path = arrayListOf(path))))
        )
        val definition = PresentationDefinition(
            id = "pd1",
            inputDescriptors = arrayListOf(
                constrained(VerificationFixtures.sdJwtDescriptor("pid"), "${'$'}.vct"),
                constrained(VerificationFixtures.mdocDescriptor("mdl"), "${'$'}['org.iso.18013.5.1']['family_name']"),
            ),
        )
        val result = runBlocking { PresentationQueryMatcher().match(PresentationQuery.PresentationDefinition(definition), wallet) }
        assertEquals(listOf("pid", "mdl"), result.entries.map { it.entry.id })
        assertEquals(listOf("vc+sd-jwt", "mso_mdoc"), result.entries.map { it.entry.format })
        @Suppress("DEPRECATION")
        val legacy = runBlocking { VerificationService().filterCredentials(wallet, definition) }
        assertEquals(result.asLegacyLists(), legacy)
    }
}
