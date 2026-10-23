package com.ewc.eudi_wallet_oidc_android.services.verification

import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.utils.generateHash
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.DID
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.dcqlRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.dcqlSdJwt
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.json
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.key
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.keyBindingJwt
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.pexRequest
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.sdJwt
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.sdJwtDescriptor
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures.transactionData
import com.ewc.eudi_wallet_oidc_android.services.verification.authorisationResponse.AuthorisationResponseHandler
import com.nimbusds.jwt.JWTClaimsSet
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Characterisation of how `transaction_data` and the SCA flag reach the key binding JWT today.
 * See [PexResponseCharacterisationTest] for the purpose of these tests.
 */
class TransactionDataCharacterisationTest {

    private val holder = key()

    private suspend fun prepare(request: PresentationRequest): Map<String, String> =
        AuthorisationResponseHandler().prepareAuthorisationResponseV2(request, listOf(listOf(sdJwt())), DID, holder, jwkList = listOf(listOf(holder)))

    private fun kbClaims(
        request: PresentationRequest,
        isScaFlow: Boolean = false,
        inherence: String? = null,
        knowledge: String? = null,
    ): JWTClaimsSet = runBlocking {
        val params = AuthorisationResponseHandler().prepareAuthorisationResponseV2(
            presentationRequest = request,
            credentialList = listOf(listOf(sdJwt())),
            did = DID,
            jwk = holder,
            isScaFlow = isScaFlow,
            jwkList = listOf(listOf(holder)),
            amrInherenceFactor = inherence,
            amrKnowledgeFactor = knowledge,
        )
        val vpToken = params.getValue("vp_token")
        val presented = if (request.dcqlQuery != null) json(vpToken).asJsonObject.getAsJsonArray("pid")[0].asString else vpToken
        keyBindingJwt(presented).jwtClaimsSet
    }

    @Test
    fun `SCA flag puts response_mode and the given amr factors in the KB-JWT`() {
        val claims = kbClaims(dcqlRequest(dcqlSdJwt("pid")), isScaFlow = true, inherence = "fingerprint_device", knowledge = "other")

        assertEquals("direct_post", claims.getStringClaim("response_mode"))
        val amr = claims.getClaim("amr") as List<*>
        assertEquals(
            listOf(
                mapOf("possession" to "key_in_local_native_wscd"),
                mapOf("inherence" to "fingerprint_device"),
                mapOf("knowledge" to "other"),
            ),
            amr,
        )
    }

    @Test
    fun `SCA flag without factors sends possession alone`() {
        val claims = kbClaims(dcqlRequest(dcqlSdJwt("pid")), isScaFlow = true)
        assertEquals(listOf(mapOf("possession" to "key_in_local_native_wscd")), claims.getClaim("amr"))
    }

    @Test
    fun `SCA is detected from a urn eudi sca transaction type when the flag is off`() {
        val request = dcqlRequest(dcqlSdJwt("pid"), transactionData = listOf(transactionData("urn:eudi:sca:payment", "pid")))
        val claims = kbClaims(request, isScaFlow = false, inherence = "fingerprint_device")

        assertEquals("direct_post", claims.getStringClaim("response_mode"))
        assertEquals(2, (claims.getClaim("amr") as List<*>).size)
    }

    @Test
    fun `a payment_data transaction type is not SCA`() {
        val request = dcqlRequest(dcqlSdJwt("pid"), transactionData = listOf(transactionData("payment_data", "pid")))
        val claims = kbClaims(request)

        assertNull(claims.getClaim("response_mode"))
        assertNull(claims.getClaim("amr"))
    }

    @Test
    fun `a transaction entry naming this credential id is hashed into the KB-JWT`() {
        val entry = transactionData("urn:eudi:sca:payment", "pid")
        val claims = kbClaims(dcqlRequest(dcqlSdJwt("pid"), transactionData = listOf(entry)))

        assertEquals(listOf(generateHash(entry)), claims.getClaim("transaction_data_hashes"))
        assertEquals("sha-256", claims.getStringClaim("transaction_data_hashes_alg"))
    }

    @Test
    fun `a transaction entry naming an input descriptor id is hashed on the PEX path too`() {
        val entry = transactionData("urn:eudi:sca:payment", "pid")
        val claims = kbClaims(pexRequest(sdJwtDescriptor("pid"), transactionData = listOf(entry)))

        assertEquals(listOf(generateHash(entry)), claims.getClaim("transaction_data_hashes"))
    }

    @Test
    fun `a transaction entry naming an id the query does not request leaves nothing to send`() {
        val entry = transactionData("urn:eudi:sca:payment", "someone-else")
        val params = runBlocking { prepare(dcqlRequest(dcqlSdJwt("pid"), transactionData = listOf(entry))) }
        // Before leg 6 this was ignored; section 8.5 lists it as invalid_transaction_data.
        assertTrue(params.isEmpty())
    }

    @Test
    fun `an entry naming another requested credential adds no hashes to this one`() {
        val entry = transactionData("urn:eudi:sca:payment", "other")
        val request = dcqlRequest(dcqlSdJwt("pid"), dcqlSdJwt("other"), transactionData = listOf(entry))
        val params = runBlocking {
            AuthorisationResponseHandler().prepareAuthorisationResponseV2(request, listOf(listOf(sdJwt()), emptyList()), DID, holder, jwkList = listOf(listOf(holder)))
        }
        val presented = json(params.getValue("vp_token")).asJsonObject.getAsJsonArray("pid")[0].asString
        assertNull(keyBindingJwt(presented).jwtClaimsSet.getClaim("transaction_data_hashes"))
    }

    @Test
    fun `every transaction entry naming the credential is hashed in request order`() {
        val first = transactionData("urn:eudi:sca:payment", "pid")
        val second = transactionData("urn:eudi:sca:emandate", "pid")
        val claims = kbClaims(dcqlRequest(dcqlSdJwt("pid"), transactionData = listOf(first, second)))

        // Before leg 6 only the first was hashed.
        assertEquals(listOf(generateHash(first), generateHash(second)), claims.getClaim("transaction_data_hashes"))
    }

    @Test
    fun `a transaction entry that is not base64url JSON leaves nothing to send`() {
        val params = runBlocking { prepare(dcqlRequest(dcqlSdJwt("pid"), transactionData = listOf("not base64url!"))) }
        // Before leg 6 this was ignored.
        assertTrue(params.isEmpty())
    }
}
