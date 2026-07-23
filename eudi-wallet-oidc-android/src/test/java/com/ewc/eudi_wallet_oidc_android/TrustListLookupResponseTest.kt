package com.ewc.eudi_wallet_oidc_android

import com.ewc.eudi_wallet_oidc_android.models.TrustListLookupResponse
import com.ewc.eudi_wallet_oidc_android.models.TrustServiceStatus
import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The OWS Trust List lookup returns `entries` (a list); older deployments returned a single
 * `entry`. Both must parse, otherwise every organisation silently resolves to "not trusted".
 */
class TrustListLookupResponseTest {

    private val gson = Gson()

    private val entriesShape = """
    {
      "match": true,
      "entries": [
        {
          "status": "granted",
          "provider": { "tSPName": "University A", "countryName": "SE" },
          "service": {
            "serviceTypeIdentifier": "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q",
            "serviceStatus": "https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted/",
            "statusStartingTime": "2025-01-31T23:00:00Z",
            "serviceName": "University A",
            "did": "did:key:z2dmzD81#z2dmzD81",
            "kid": "",
            "jwksURI": ""
          },
          "matchType": "did",
          "certificateValid": true,
          "certificateDetails": [],
          "trustList": { "name": "EWC-TL.xml", "url": "https://trustlist.nxd.foundation/trust-lists/legacy/EWC-TL.xml" },
          "permittedCredentials": [
            {"format": "dc+sd-jwt", "vct": "QEAA-only"}
          ]
        }
      ]
    }
    """.trimIndent()

    private val legacyShape = """
    {
      "match": true,
      "entry": {
        "status": "granted",
        "provider": { "tSPName": "Old Provider" },
        "service": { "serviceTypeIdentifier": "http://uri.etsi.org/TrstSvc/Svctype/EAA" }
      }
    }
    """.trimIndent()

    @Test
    fun `entries shape parses and exposes the service section`() {
        val response = gson.fromJson(entriesShape, TrustListLookupResponse::class.java)

        assertTrue(response.match)
        assertEquals(1, response.matchedEntries.size)

        val entry = response.matchedEntries.first()
        assertEquals("University A", entry.provider?.tSPName)
        assertEquals("http://uri.etsi.org/TrstSvc/Svctype/EAA/Q", entry.service?.serviceTypeIdentifier)
        assertEquals("did:key:z2dmzD81#z2dmzD81", entry.service?.did)
        assertEquals("", entry.service?.kid)
        assertEquals(
            "https://trustlist.nxd.foundation/trust-lists/legacy/EWC-TL.xml",
            entry.trustList?.url
        )
        assertEquals(1, entry.permittedCredentials.size)
        assertEquals("QEAA-only", entry.permittedCredentials.first().vct)
    }

    @Test
    fun `legacy single-entry shape still resolves through matchedEntries`() {
        val response = gson.fromJson(legacyShape, TrustListLookupResponse::class.java)

        assertEquals(1, response.matchedEntries.size)
        assertEquals("Old Provider", response.matchedEntries.first().provider?.tSPName)
    }

    @Test
    fun `no match yields no entries`() {
        val response = gson.fromJson("""{"match": false}""", TrustListLookupResponse::class.java)

        assertTrue(response.matchedEntries.isEmpty())
    }

    @Test
    fun `status parses with or without a trailing slash and either scheme`() {
        assertEquals(
            TrustServiceStatus.GRANTED,
            TrustServiceStatus.from("https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted/")
        )
        assertEquals(
            TrustServiceStatus.GRANTED,
            TrustServiceStatus.from("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted")
        )
        assertEquals(
            TrustServiceStatus.WITHDRAWN,
            TrustServiceStatus.from("https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn")
        )
        assertEquals(
            TrustServiceStatus.WITHDRAWN,
            TrustServiceStatus.from("https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn/")
        )
        assertEquals(TrustServiceStatus.GRANTED, TrustServiceStatus.from("granted"))
        assertEquals(TrustServiceStatus.GRANTED, TrustServiceStatus.from("  GRANTED  "))
        // Anything unrecognised is refused, not assumed good.
        assertEquals(TrustServiceStatus.UNKNOWN, TrustServiceStatus.from(null))
        assertEquals(TrustServiceStatus.UNKNOWN, TrustServiceStatus.from(""))
        assertEquals(TrustServiceStatus.UNKNOWN, TrustServiceStatus.from(".../Svcstatus/suspended"))
    }

    @Test
    fun `withdrawn entries are filtered out of grantedEntries`() {
        val mixed = """
        {
          "match": true,
          "entries": [
            {
              "status": "withdrawn",
              "service": {
                "serviceTypeIdentifier": "http://uri.etsi.org/TrstSvc/Svctype/EAA",
                "serviceStatus": "https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"
              },
              "trustList": { "url": "https://example.org/A-TL.xml" }
            },
            {
              "status": "granted",
              "service": {
                "serviceTypeIdentifier": "http://uri.etsi.org/TrstSvc/Svctype/WRPAC",
                "serviceStatus": "https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted/"
              },
              "trustList": { "url": "https://example.org/B-TL.xml" }
            }
          ]
        }
        """.trimIndent()

        val response = gson.fromJson(mixed, TrustListLookupResponse::class.java)

        assertEquals(2, response.matchedEntries.size)
        assertEquals(1, response.grantedEntries.size)
        assertEquals(
            "http://uri.etsi.org/TrstSvc/Svctype/WRPAC",
            response.grantedEntries.first().service?.serviceTypeIdentifier
        )
    }

    @Test
    fun `entry level status is used when serviceStatus is absent`() {
        val json = """
        {"match": true, "entries": [
          {"status": "granted", "service": {"serviceTypeIdentifier": "x"}},
          {"status": "withdrawn", "service": {"serviceTypeIdentifier": "y"}}
        ]}
        """.trimIndent()

        val response = gson.fromJson(json, TrustListLookupResponse::class.java)

        assertEquals(1, response.grantedEntries.size)
        assertEquals("x", response.grantedEntries.first().service?.serviceTypeIdentifier)
    }

    @Test
    fun `entry with no status at all is refused`() {
        val json = """{"match": true, "entries": [{"service": {"serviceTypeIdentifier": "x"}}]}"""

        val response = gson.fromJson(json, TrustListLookupResponse::class.java)

        assertEquals(1, response.matchedEntries.size)
        assertTrue(response.grantedEntries.isEmpty())
    }
}
