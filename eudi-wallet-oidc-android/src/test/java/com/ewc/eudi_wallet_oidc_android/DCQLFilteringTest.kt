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
    fun `test dc+sd-jwt credential filtering success`() {
        val claim = DcqlClaim(id = "c1", path = listOf("age", "value"))
        val credential = CredentialList(
            id = "cred1",
            format = "dc+sd-jwt",
            meta = Meta(vctValues = arrayListOf("https://example.com/vct")),
            claims = listOf(claim)
        )
        val dcql = DCQL(credentials = listOf(credential))

        val jsonCredential = """
            {
                "vct": "https://example.com/vct",
                "name": "John Doe",
                "age":{
                    "value": 30
                }
            }
        """.trimIndent()

        val result = DCQLFiltering.filterCredentialsUsingDCQL(dcql, listOf(jsonCredential))
        assertEquals(1, result.size)
        assertEquals(1, result[0].size)
        assertEquals(jsonCredential, result[0][0])
    }

    @Test
    fun `test dc+sd-jwt credential filtering fails due to unmatched vct`() {
        val claim = DcqlClaim(id = "c1", path = listOf("name"))
        val credential = CredentialList(
            id = "cred1",
            format = "dc+sd-jwt",
            meta = Meta(vctValues = arrayListOf("https://example.com/vct")),
            claims = listOf(claim)
        )
        val dcql = DCQL(credentials = listOf(credential))

        val jsonCredential = """
            {
                "vct": "https://invalid.com/vct",
                "name": "John Doe"
            }
        """.trimIndent()

        val result = DCQLFiltering.filterCredentialsUsingDCQL(dcql, listOf(jsonCredential))
        assertEquals(1, result.size)
        assertTrue(result[0].isEmpty())
    }

    @Test
    fun `test dc+sd-jwt credential filtering fails due to missing claim`() {
        val claim = DcqlClaim(id = "c1", path = listOf("age"))
        val credential = CredentialList(
            id = "cred1",
            format = "dc+sd-jwt",
            meta = Meta(vctValues = arrayListOf("https://example.com/vct")),
            claims = listOf(claim)
        )
        val dcql = DCQL(credentials = listOf(credential))

        val jsonCredential = """
            {
                "vct": "https://example.com/vct",
                "name": "John Doe"
            }
        """.trimIndent()

        val result = DCQLFiltering.filterCredentialsUsingDCQL(dcql, listOf(jsonCredential))
        assertEquals(1, result.size)
        assertTrue(result[0].isEmpty())
    }

    @Test
    fun `test multiple credentials with mixed validity`() {
        val claim = DcqlClaim(id = "c1", path = listOf("name"))
        val credential = CredentialList(
            id = "cred1",
            format = "dc+sd-jwt",
            meta = Meta(vctValues = arrayListOf("https://example.com/vct")),
            claims = listOf(claim)
        )
        val dcql = DCQL(credentials = listOf(credential))

        val validCredential = """
            {
                "vct": "https://example.com/vct",
                "name": "John Doe"
            }
        """.trimIndent()

        val invalidCredential = """
            {
                "vct": "https://wrong.com/vct",
                "name": "Jane Doe"
            }
        """.trimIndent()

        val result = DCQLFiltering.filterCredentialsUsingDCQL(
            dcql,
            listOf(validCredential, invalidCredential)
        )
        assertEquals(1, result.size)
        assertEquals(1, result[0].size)
        assertEquals(validCredential, result[0][0])
    }

    // mso mdoc test cases
    @Test
    fun `test mso_mdoc credential filtering success`() {
        val claims = listOf(
            DcqlClaim(id = "c1", namespace = "org.iso.7367.1", claimName = "vehicle_holder"),
            DcqlClaim(id = "c2", namespace = "org.iso.18013.5.1", claimName = "first_name")
        )
        val credential = CredentialList(
            id = "cred1",
            format = "mso_mdoc",
            meta = Meta(doctypeValue = "org.iso.7367.1.mVRC"),
            claims = claims
        )
        val dcql = DCQL(credentials = listOf(credential))

        val validCredential = """
    {
        "docType": "org.iso.7367.1.mVRC",
        "org.iso.7367.1": {
            "vehicle_holder": "John Doe"
        },
        "org.iso.18013.5.1": {
            "first_name": "John"
        }
    }
    """.trimIndent()

        val result = DCQLFiltering.filterCredentialsUsingDCQL(dcql, listOf(validCredential))
        assertEquals(1, result.size)
        assertEquals(1, result[0].size)
        assertEquals(validCredential, result[0][0])
    }

    @Test
    fun `test mso_mdoc credential filtering fails due to unmatched docType`() {
        val claims = listOf(
            DcqlClaim(id = "c1", namespace = "org.iso.7367.1", claimName = "vehicle_holder")
        )
        val credential = CredentialList(
            id = "cred1",
            format = "mso_mdoc",
            meta = Meta(doctypeValue = "org.iso.7367.1.mVRC"),
            claims = claims
        )
        val dcql = DCQL(credentials = listOf(credential))

        val invalidDocTypeCredential = """
    {
        "docType": "org.wrong.docType",
        "org.iso.7367.1": {
            "vehicle_holder": "John Doe"
        }
    }
    """.trimIndent()

        val result = DCQLFiltering.filterCredentialsUsingDCQL(dcql, listOf(invalidDocTypeCredential))
        assertEquals(1, result.size)
        assertTrue(result[0].isEmpty())
    }

    @Test
    fun `test mso_mdoc credential filtering fails due to missing claim`() {
        val claims = listOf(
            DcqlClaim(id = "c1", namespace = "org.iso.7367.1", claimName = "vehicle_holder"),
            DcqlClaim(id = "c2", namespace = "org.iso.18013.5.1", claimName = "first_name")
        )
        val credential = CredentialList(
            id = "cred1",
            format = "mso_mdoc",
            meta = Meta(doctypeValue = "org.iso.7367.1.mVRC"),
            claims = claims
        )
        val dcql = DCQL(credentials = listOf(credential))

        val missingClaimCredential = """
    {
        "docType": "org.iso.7367.1.mVRC",
        "org.iso.7367.1": {
            "vehicle_holder": "John Doe"
        }
    }
    """.trimIndent()

        val result = DCQLFiltering.filterCredentialsUsingDCQL(dcql, listOf(missingClaimCredential))
        assertEquals(1, result.size)
        assertTrue(result[0].isEmpty())
    }

    @Test
    fun `test multiple mso_mdoc credentials with mixed validity`() {
        val claims = listOf(
            DcqlClaim(id = "c1", namespace = "org.iso.7367.1", claimName = "vehicle_holder")
        )
        val credential = CredentialList(
            id = "cred1",
            format = "mso_mdoc",
            meta = Meta(doctypeValue = "org.iso.7367.1.mVRC"),
            claims = claims
        )
        val dcql = DCQL(credentials = listOf(credential))

        val validCredential = """
    {
        "docType": "org.iso.7367.1.mVRC",
        "org.iso.7367.1": {
            "vehicle_holder": "John Doe"
        }
    }
    """.trimIndent()

        val invalidCredential = """
    {
        "docType": "org.iso.7367.1.mVRC",
        "org.iso.9999.1": {
            "some_other_claim": "Not related"
        }
    }
    """.trimIndent()

        val result = DCQLFiltering.filterCredentialsUsingDCQL(
            dcql,
            listOf(validCredential, invalidCredential)
        )
        assertEquals(1, result.size)
        assertEquals(1, result[0].size)
        assertEquals(validCredential, result[0][0])
    }


}
