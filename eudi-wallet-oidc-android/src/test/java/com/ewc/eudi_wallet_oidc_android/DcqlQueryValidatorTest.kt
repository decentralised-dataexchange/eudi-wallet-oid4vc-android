package com.ewc.eudi_wallet_oidc_android

import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.services.dcql.DcqlQueryValidator
import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Queries are given as JSON and parsed with Gson, exactly as the SDK parses a
 * `dcql_query` parameter or request object payload, so the tests exercise the same
 * model the live path validates.
 */
class DcqlQueryValidatorTest {

    private fun validate(json: String): List<String> =
        DcqlQueryValidator.validate(Gson().fromJson(json, DCQL::class.java))

    private fun assertValid(json: String) {
        val errors = validate(json)
        assertTrue("expected no violations but got $errors", errors.isEmpty())
    }

    private fun assertViolation(json: String, expected: String) {
        val errors = validate(json)
        assertTrue(
            "expected a violation containing '$expected' but got $errors",
            errors.any { it.contains(expected) }
        )
    }

    // ---- valid queries -------------------------------------------------------------------

    @Test
    fun `sd-jwt query with vct_values and claims is valid`() {
        assertValid(
            """
            {"credentials":[{"id":"pid","format":"dc+sd-jwt",
              "meta":{"vct_values":["urn:eudi:pid:1"]},
              "claims":[{"path":["given_name"]},{"path":["address","street_address"]}]}]}
            """
        )
    }

    @Test
    fun `mdoc query with doctype_value and two-component paths is valid`() {
        assertValid(
            """
            {"credentials":[{"id":"mdl","format":"mso_mdoc",
              "meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
              "claims":[{"path":["org.iso.18013.5.1","family_name"],"intent_to_retain":false}]}]}
            """
        )
    }

    @Test
    fun `jwt_vc_json query with type_values is valid`() {
        assertValid(
            """
            {"credentials":[{"id":"vc","format":"jwt_vc_json",
              "meta":{"type_values":[["VerifiableCredential","IDCredential"]]},
              "claims":[{"path":["credentialSubject","family_name"]}]}]}
            """
        )
    }

    @Test
    fun `ldp_vc query with type_values is valid`() {
        assertValid(
            """
            {"credentials":[{"id":"vc","format":"ldp_vc","meta":{"type_values":[["VerifiableCredential"]]}}]}
            """
        )
    }

    @Test
    fun `query with claim_sets and credential_sets is valid`() {
        assertValid(
            """
            {"credentials":[
               {"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
                "claims":[{"id":"a","path":["given_name"]},{"id":"b","path":["family_name"]},{"id":"c","path":["age_over_18"]}],
                "claim_sets":[["a","b"],["c"]]},
               {"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
                "claims":[{"path":["org.iso.18013.5.1","family_name"]}]}],
             "credential_sets":[{"options":[["pid"],["mdl"]],"required":true,"purpose":"Identification"}]}
            """
        )
    }

    @Test
    fun `query without claims requests the mandatory claims only and is valid`() {
        assertValid("""{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}]}""")
    }

    @Test
    fun `values with strings integers and booleans are valid`() {
        assertValid(
            """
            {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
              "claims":[{"path":["nationalities"],"values":["DE","SE"]},
                        {"path":["age"],"values":[18,21]},
                        {"path":["age_over_18"],"values":[true]}]}]}
            """
        )
    }

    @Test
    fun `trusted_authorities with known types are valid`() {
        assertValid(
            """
            {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
              "trusted_authorities":[{"type":"aki","values":["s9tIpPmhxdiuNkHMEWNpYim8S8Y"]},
                                     {"type":"etsi_tl","values":["https://lotl.example/eu-lotl.xml"]},
                                     {"type":"openid_federation","values":["https://federation.example"]}]}]}
            """
        )
    }

    @Test
    fun `unknown members are ignored`() {
        assertValid(
            """
            {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
              "require_cryptographic_holder_binding":false,"future_member":{"x":1},
              "claims":[{"path":["given_name"],"another_member":true}]}],
             "something_else":[]}
            """
        )
    }

    // ---- top level -----------------------------------------------------------------------

    @Test
    fun `null query is rejected`() {
        val errors = DcqlQueryValidator.validate(null)
        assertEquals(listOf("dcql_query is missing"), errors)
    }

    @Test
    fun `missing credentials is rejected`() {
        assertViolation("""{}""", "credentials must be a non-empty array")
    }

    @Test
    fun `empty credentials is rejected`() {
        assertViolation("""{"credentials":[]}""", "credentials must be a non-empty array")
    }

    @Test
    fun `empty credential_sets is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]}}],"credential_sets":[]}""",
            "credential_sets must be a non-empty array when present"
        )
    }

    // ---- credential query ----------------------------------------------------------------

    @Test
    fun `missing credential id is rejected`() {
        assertViolation(
            """{"credentials":[{"format":"dc+sd-jwt","meta":{"vct_values":["v"]}}]}""",
            "credentials[0].id is required"
        )
    }

    @Test
    fun `credential id with illegal characters is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"my credential","format":"dc+sd-jwt","meta":{"vct_values":["v"]}}]}""",
            "credentials[0].id must contain only letters, digits, '_' or '-'"
        )
    }

    @Test
    fun `duplicate credential ids are rejected`() {
        assertViolation(
            """
            {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]}},
                            {"id":"pid","format":"mso_mdoc","meta":{"doctype_value":"d"}}]}
            """,
            "credentials[1].id 'pid' is not unique"
        )
    }

    @Test
    fun `missing format is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"pid","meta":{"vct_values":["v"]}}]}""",
            "credentials[0].format is required"
        )
    }

    @Test
    fun `unsupported format is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"pid","format":"vc+sd-jwt","meta":{"vct_values":["v"]}}]}""",
            "credentials[0].format 'vc+sd-jwt' is not supported"
        )
    }

    @Test
    fun `missing meta is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt"}]}""",
            "credentials[0].meta is required"
        )
    }

    @Test
    fun `sd-jwt without vct_values is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{}}]}""",
            "credentials[0].meta.vct_values must be a non-empty array of strings"
        )
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":[]}}]}""",
            "credentials[0].meta.vct_values must be a non-empty array of strings"
        )
    }

    @Test
    fun `mdoc without doctype_value is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{}}]}""",
            "credentials[0].meta.doctype_value is required"
        )
    }

    @Test
    fun `jwt_vc_json without type_values is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"vc","format":"jwt_vc_json","meta":{}}]}""",
            "credentials[0].meta.type_values must be a non-empty array of non-empty string arrays"
        )
    }

    @Test
    fun `jwt_vc_json with an empty inner type array is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"vc","format":"jwt_vc_json","meta":{"type_values":[[]]}}]}""",
            "credentials[0].meta.type_values must be a non-empty array of non-empty string arrays"
        )
    }

    @Test
    fun `empty claims array is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[]}]}""",
            "credentials[0].claims must be a non-empty array when present"
        )
    }

    @Test
    fun `empty trusted_authorities is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"trusted_authorities":[]}]}""",
            "credentials[0].trusted_authorities must be a non-empty array when present"
        )
    }

    @Test
    fun `trusted authority with unknown type is rejected`() {
        assertViolation(
            """
            {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},
              "trusted_authorities":[{"type":"x509_san_dns","values":["verifier.example"]}]}]}
            """,
            "credentials[0].trusted_authorities[0].type 'x509_san_dns' is not supported"
        )
    }

    @Test
    fun `trusted authority without values is rejected`() {
        assertViolation(
            """
            {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},
              "trusted_authorities":[{"type":"aki","values":[]}]}]}
            """,
            "credentials[0].trusted_authorities[0].values must be a non-empty array of strings"
        )
    }

    // ---- claims query --------------------------------------------------------------------

    @Test
    fun `claim without path is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"id":"a"}]}]}""",
            "credentials[0].claims[0].path must be a non-empty array"
        )
    }

    @Test
    fun `claim with empty path is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"path":[]}]}]}""",
            "credentials[0].claims[0].path must be a non-empty array"
        )
    }

    @Test
    fun `legacy mdoc namespace and claim_name without path is rejected`() {
        assertViolation(
            """
            {"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
              "claims":[{"namespace":"org.iso.18013.5.1","claim_name":"family_name"}]}]}
            """,
            "credentials[0].claims[0].path must be a non-empty array"
        )
    }

    @Test
    fun `mdoc path with one component is rejected`() {
        assertViolation(
            """
            {"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"d"},
              "claims":[{"path":["family_name"]}]}]}
            """,
            "credentials[0].claims[0].path must have exactly two string components"
        )
    }

    @Test
    fun `mdoc path with three components is rejected`() {
        assertViolation(
            """
            {"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"d"},
              "claims":[{"path":["org.iso.18013.5.1","address","street"]}]}]}
            """,
            "credentials[0].claims[0].path must have exactly two string components"
        )
    }

    @Test
    fun `mdoc path with a null component is rejected`() {
        assertViolation(
            """
            {"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"d"},
              "claims":[{"path":["org.iso.18013.5.1",null]}]}]}
            """,
            "credentials[0].claims[0].path must have exactly two string components"
        )
    }

    @Test
    fun `claim id with illegal characters is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"id":"a.b","path":["x"]}]}]}""",
            "credentials[0].claims[0].id must contain only letters, digits, '_' or '-'"
        )
    }

    @Test
    fun `duplicate claim ids are rejected`() {
        assertViolation(
            """
            {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},
              "claims":[{"id":"a","path":["x"]},{"id":"a","path":["y"]}]}]}
            """,
            "credentials[0].claims[1].id 'a' is not unique"
        )
    }

    @Test
    fun `empty values array is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"path":["x"],"values":[]}]}]}""",
            "credentials[0].claims[0].values must be a non-empty array when present"
        )
    }

    @Test
    fun `values with an object or a decimal are rejected`() {
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"path":["x"],"values":[{"a":1}]}]}]}""",
            "credentials[0].claims[0].values may only contain strings, integers or booleans"
        )
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"path":["x"],"values":[1.5]}]}]}""",
            "credentials[0].claims[0].values may only contain strings, integers or booleans"
        )
    }

    // ---- claim_sets ----------------------------------------------------------------------

    @Test
    fun `claim_sets without claims is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claim_sets":[["a"]]}]}""",
            "credentials[0].claim_sets must not be present when claims is absent"
        )
    }

    @Test
    fun `empty claim_sets is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"id":"a","path":["x"]}],"claim_sets":[]}]}""",
            "credentials[0].claim_sets must be a non-empty array when present"
        )
    }

    @Test
    fun `claim id is required when claim_sets is present`() {
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"path":["x"]}],"claim_sets":[["a"]]}]}""",
            "credentials[0].claims[0].id is required when claim_sets is present"
        )
    }

    @Test
    fun `claim_sets referencing an unknown claim id is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"id":"a","path":["x"]}],"claim_sets":[["a","b"]]}]}""",
            "credentials[0].claim_sets[0] references unknown claim id 'b'"
        )
    }

    @Test
    fun `empty claim set option is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"id":"a","path":["x"]}],"claim_sets":[[]]}]}""",
            "credentials[0].claim_sets[0] must be a non-empty array"
        )
    }

    // ---- credential_sets -----------------------------------------------------------------

    @Test
    fun `credential set without options is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]}}],"credential_sets":[{"required":true}]}""",
            "credential_sets[0].options must be a non-empty array"
        )
    }

    @Test
    fun `credential set with an empty option is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]}}],"credential_sets":[{"options":[[]]}]}""",
            "credential_sets[0].options[0] must be a non-empty array"
        )
    }

    @Test
    fun `credential set referencing an unknown credential id is rejected`() {
        assertViolation(
            """{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]}}],"credential_sets":[{"options":[["pid","mdl"]]}]}""",
            "credential_sets[0].options[0] references unknown credential id 'mdl'"
        )
    }

    // ---- reporting -----------------------------------------------------------------------

    @Test
    fun `all violations are reported in document order`() {
        val errors = validate(
            """
            {"credentials":[{"id":"bad id","format":"unknown","meta":{}},
                            {"format":"mso_mdoc","meta":{"doctype_value":"d"},"claims":[{"path":["one"]}]}],
             "credential_sets":[{"options":[["nope"]]}]}
            """
        )
        assertEquals(
            listOf(
                "credentials[0].id must contain only letters, digits, '_' or '-'",
                "credentials[0].format 'unknown' is not supported",
                "credentials[1].id is required",
                "credentials[1].claims[0].path must have exactly two string components (namespace, element identifier) for mso_mdoc",
                "credential_sets[0].options[0] references unknown credential id 'nope'"
            ),
            errors
        )
    }
}
