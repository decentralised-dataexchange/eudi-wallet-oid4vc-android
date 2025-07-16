package com.ewc.eudi_wallet_oidc_android


import com.ewc.eudi_wallet_oidc_android.models.CredentialList
import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.models.DcqlClaim
import com.ewc.eudi_wallet_oidc_android.models.Meta
import com.ewc.eudi_wallet_oidc_android.services.DCQLFiltering
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DCQLFilteringTest {

    @Test
    fun `should return empty list when DCQL credentials is null`() {
        val dcql = DCQL(credentials = null)
        val result = DCQLFiltering.filterCredentialsUsingDCQL(dcql, listOf())

        assertTrue(result.isEmpty())
    }

    @Test
    fun `should filter dc+sd-jwt credentials matching vct and path`() {
        val dcql = DCQL(
            credentials = listOf(
                CredentialList(
                    format = "dc+sd-jwt",
                    meta = Meta(vctValues = arrayListOf("TestVCT")),
                    claims = listOf(
                        DcqlClaim(path = listOf("credentialSubject","name"))
                    )
                )
            )
        )

        val credentialJson = """
            {
              "vct": "TestVCT",
              "credentialSubject": {
                "name": "Alice"
              }
            }
        """.trimIndent()

        val result = DCQLFiltering.filterCredentialsUsingDCQL(dcql, listOf(credentialJson))

        assertEquals(1, result.size)
        assertEquals(1, result[0].size)
        assertEquals("Alice", result[0][0].fields[0].path.value)
    }

    @Test
    fun `should skip credential if vct does not match`() {
        val dcql = DCQL(
            credentials = listOf(
                CredentialList(
                    format = "dc+sd-jwt",
                    meta = Meta(vctValues = arrayListOf("ExpectedVCT")),
                    claims = listOf(
                        DcqlClaim(path = listOf("credentialSubject", "name"))
                    )
                )
            )
        )

        val credentialJson = """
            {
              "vct": "WrongVCT",
              "credentialSubject": {
                "name": "Alice"
              }
            }
        """.trimIndent()

        val result = DCQLFiltering.filterCredentialsUsingDCQL(dcql, listOf(credentialJson))

        // Only one filter, but it should not match due to wrong vct
        assertEquals(1, result.size)
        assertTrue(result[0].isEmpty())
    }

    @Test
    fun `should return only the matching credential from multiple dc+sd-jwt credentials`() {
        val dcql = DCQL(
            credentials = listOf(
                CredentialList(
                    format = "dc+sd-jwt",
                    meta = Meta(vctValues = arrayListOf("MatchVCT")),
                    claims = listOf(
                        DcqlClaim(path = listOf("credentialSubject", "name"))
                    )
                )
            )
        )

        val matchingCredential = """
            {
              "vct": "MatchVCT",
              "credentialSubject": {
                "name": "Alice"
              }
            }
        """.trimIndent()

        val wrongVctCredential = """
            {
              "vct": "WrongVCT",
              "credentialSubject": {
                "name": "Bob"
              }
            }
        """.trimIndent()

        val missingClaimCredential = """
            {
              "vct": "MatchVCT",
              "credentialSubject": {
                "age": 30
              }
            }
        """.trimIndent()

        val credentials = listOf(matchingCredential, wrongVctCredential, missingClaimCredential)

        val result = DCQLFiltering.filterCredentialsUsingDCQL(dcql, credentials)

        // One filter
        assertEquals(1, result.size)
        // Only one credential should match
        assertEquals(1, result[0].size)
        // It should be the first one (index 0)
        assertEquals(0, result[0][0].index)
        assertEquals("Alice", result[0][0].fields[0].path.value)
    }

    @Test
    fun `should return all matching credentials from multiple dc+sd-jwt credentials`() {
        val dcql = DCQL(
            credentials = listOf(
                CredentialList(
                    format = "dc+sd-jwt",
                    meta = Meta(vctValues = arrayListOf("MatchVCT")),
                    claims = listOf(
                        DcqlClaim(path = listOf("credentialSubject", "name"))
                    )
                )
            )
        )

        val credential1 = """
            {
              "vct": "MatchVCT",
              "credentialSubject": {
                "name": "Alice"
              }
            }
        """.trimIndent()

        val credential2 = """
            {
              "vct": "MatchVCT",
              "credentialSubject": {
                "name": "Bob"
              }
            }
        """.trimIndent()

        val credential3 = """
            {
              "vct": "MatchVCT",
              "credentialSubject": {
                "name": "Charlie"
              }
            }
        """.trimIndent()

        val credentials = listOf(credential1, credential2, credential3)

        val result = DCQLFiltering.filterCredentialsUsingDCQL(dcql, credentials)

        // One filter
        assertEquals(1, result.size)
        // Three matching credentials
        assertEquals(3, result[0].size)

        // Validate each match
        assertEquals("Alice", result[0][0].fields[0].path.value)
        assertEquals("Bob", result[0][1].fields[0].path.value)
        assertEquals("Charlie", result[0][2].fields[0].path.value)
    }

    @Test
    fun `should return empty when none of the dc+sd-jwt credentials match`() {
        val dcql = DCQL(
            credentials = listOf(
                CredentialList(
                    format = "dc+sd-jwt",
                    meta = Meta(vctValues = arrayListOf("ExpectedVCT")),
                    claims = listOf(
                        DcqlClaim(path = listOf("credentialSubject", "name"))
                    )
                )
            )
        )

        val credential1 = """
            {
              "vct": "WrongVCT",
              "credentialSubject": {
                "name": "Alice"
              }
            }
        """.trimIndent()

        val credential2 = """
            {
              "vct": "ExpectedVCT",
              "credentialSubject": {
                "age": 30
              }
            }
        """.trimIndent()

        val credential3 = """
            {
              "type": "SomeOtherType",
              "data": {}
            }
        """.trimIndent()

        val credentials = listOf(credential1, credential2, credential3)

        val result = DCQLFiltering.filterCredentialsUsingDCQL(dcql, credentials)

        // One filter
        assertEquals(1, result.size)
        // No matching credentials
        assertTrue(result[0].isEmpty())
    }

    @Test
    fun `should match mso_mdoc credential with valid namespace and claimName`() {
        val dcql = DCQL(
            credentials = listOf(
                CredentialList(
                    format = "mso_mdoc",
                    claims = listOf(
                        DcqlClaim(
                            namespace = "org.iso.18013.5.1",
                            claimName = "family_name"
                        )
                    )
                )
            )
        )

        val mdocCredential = """
            {
              "org.iso.18013.5.1": {
                "family_name": "Smith"
              }
            }
        """.trimIndent()

        val result = DCQLFiltering.filterCredentialsUsingDCQL(dcql, listOf(mdocCredential))

        // One filter
        assertEquals(1, result.size)
        // One matched credential
        assertEquals(1, result[0].size)

        val matched = result[0][0]
        assertEquals(0, matched.index)
        assertEquals("Smith", matched.fields[0].path.value)
        assertEquals("$['org.iso.18013.5.1']['family_name']", matched.fields[0].path.path)
    }

    @Test
    fun `should skip mso_mdoc credential when namespace is wrong`() {
        val dcql = DCQL(
            credentials = listOf(
                CredentialList(
                    format = "mso_mdoc",
                    claims = listOf(
                        DcqlClaim(
                            namespace = "org.iso.18013.5.1",
                            claimName = "family_name"
                        )
                    )
                )
            )
        )

        val wrongNamespaceCredential = """
            {
              "org.example.wrong.ns": {
                "family_name": "Smith"
              }
            }
        """.trimIndent()

        val result = DCQLFiltering.filterCredentialsUsingDCQL(dcql, listOf(wrongNamespaceCredential))

        // One filter
        assertEquals(1, result.size)
        // No matches
        assertTrue(result[0].isEmpty())
    }

    @Test
    fun `should return only matching mso_mdoc credentials among mixed ones`() {
        val dcql = DCQL(
            credentials = listOf(
                CredentialList(
                    format = "mso_mdoc",
                    claims = listOf(
                        DcqlClaim(
                            namespace = "org.iso.18013.5.1",
                            claimName = "family_name"
                        )
                    )
                )
            )
        )

        val valid1 = """
            {
              "org.iso.18013.5.1": {
                "family_name": "Smith"
              }
            }
        """.trimIndent()

        val wrongNamespace = """
            {
              "org.other.namespace": {
                "family_name": "Johnson"
              }
            }
        """.trimIndent()

        val wrongClaimName = """
            {
              "org.iso.18013.5.1": {
                "given_name": "Alice"
              }
            }
        """.trimIndent()

        val valid2 = """
            {
              "org.iso.18013.5.1": {
                "family_name": "Brown"
              }
            }
        """.trimIndent()

        val credentials = listOf(valid1, wrongNamespace, wrongClaimName, valid2)

        val result = DCQLFiltering.filterCredentialsUsingDCQL(dcql, credentials)

        // One filter
        assertEquals(1, result.size)
        // Two matches expected
        assertEquals(2, result[0].size)

        // First match (index 0)
        assertEquals(0, result[0][0].index)
        assertEquals("Smith", result[0][0].fields[0].path.value)

        // Second match (index 3)
        assertEquals(3, result[0][1].index)
        assertEquals("Brown", result[0][1].fields[0].path.value)
    }

}
