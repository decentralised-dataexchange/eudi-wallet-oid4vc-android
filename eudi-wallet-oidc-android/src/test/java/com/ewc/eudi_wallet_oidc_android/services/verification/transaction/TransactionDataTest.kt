package com.ewc.eudi_wallet_oidc_android.services.verification.transaction

import com.ewc.eudi_wallet_oidc_android.models.CredentialList
import com.ewc.eudi_wallet_oidc_android.models.DCQL
import com.ewc.eudi_wallet_oidc_android.models.Meta
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.issue.authorization.WalletIdentity
import com.ewc.eudi_wallet_oidc_android.services.utils.generateHash
import com.ewc.eudi_wallet_oidc_android.services.verification.VerificationFixtures
import com.ewc.eudi_wallet_oidc_android.services.verification.presentation.SelectedCredential
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestOutcome
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestPolicy
import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestResolver
import com.ewc.eudi_wallet_oidc_android.services.verification.response.PresentationOutcome
import com.ewc.eudi_wallet_oidc_android.services.verification.response.PresentationSubmitter
import com.google.gson.Gson
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URLEncoder
import java.security.MessageDigest
import java.util.Base64

/** One case per row of the leg 6 matrix in VERIFICATION_REVAMP_PLAN_ANDROID.md. */
class TransactionDataTest {

    private fun entry(json: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray())
    private fun sca(vararg ids: String, alg: String? = null) =
        entry("""{"type":"urn:eudi:sca:payment:1","credential_ids":[${ids.joinToString(",") { "\"$it\"" }}]${alg?.let { ",\"transaction_data_hashes_alg\":$it" } ?: ""}}""")

    private fun request(vararg data: String, binding: Boolean = true) = PresentationRequest(
        clientId = "redirect_uri:${VerificationFixtures.RESPONSE_URI}", nonce = "n", responseType = "vp_token",
        responseMode = "dc_api",
        dcqlQuery = DCQL(credentials = listOf(
            CredentialList(id = "pid", format = "dc+sd-jwt", meta = Meta(vctValues = arrayListOf(VerificationFixtures.VCT)), requireCryptographicHolderBinding = binding),
            CredentialList(id = "iban", format = "dc+sd-jwt", meta = Meta(vctValues = arrayListOf("urn:iban"))),
        )),
        transactionDdata = ArrayList(data.toList()),
    )

    private fun invalid(block: () -> Unit): String {
        try { block() } catch (e: TransactionData.InvalidTransactionData) { return e.message!! }
        throw AssertionError("expected invalid_transaction_data")
    }

    @Test
    fun `6_1 and 6_2 every entry naming the id is hashed in order, and only those`() {
        val a = sca("pid"); val b = sca("pid", "iban"); val c = sca("iban")
        val entries = TransactionData.entries(request(a, b, c))
        assertEquals(TransactionDataHashes("sha-256", listOf(generateHash(a)!!, generateHash(b)!!)), TransactionData.hashes(entries, "pid"))
        assertEquals(listOf(generateHash(b), generateHash(c)), TransactionData.hashes(entries, "iban")!!.hashes)
        assertNull(TransactionData.hashes(entries, "missing"))
    }

    @Test
    fun `6_4 an id the query does not request is invalid`() {
        assertTrue(invalid { TransactionData.entries(request(sca("passport"))) }.contains("passport"))
    }

    @Test
    fun `6_5 a malformed entry or one missing type or credential_ids is invalid`() {
        invalid { TransactionData.entries(request("not base64url!")) }
        invalid { TransactionData.entries(request(entry("""{"credential_ids":["pid"]}"""))) }
        invalid { TransactionData.entries(request(entry("""{"type":"x","credential_ids":[]}"""))) }
    }

    @Test
    fun `6_6 transaction_data_hashes_alg selects and echoes the algorithm`() {
        val raw = sca("pid", alg = """["sha-512","sha-256"]""")
        val hashes = TransactionData.hashes(TransactionData.entries(request(raw)), "pid")!!
        assertEquals("sha-256", hashes.algorithm) // first supported in preference order present in the list
        val only512 = sca("pid", alg = """["sha-512"]""")
        val h512 = TransactionData.hashes(TransactionData.entries(request(only512)), "pid")!!
        assertEquals("sha-512", h512.algorithm)
        assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-512").digest(only512.toByteArray())), h512.hashes.single())
        invalid { TransactionData.entries(request(sca("pid", alg = """["md5"]"""))) }
        invalid { TransactionData.hashes(TransactionData.entries(request(only512, sca("pid"))), "pid") }
    }

    @Test
    fun `6_8 SCA is detected from any entry and not from payment_data`() {
        val pwa = entry("""{"type":"payment_data","credential_ids":["pid"]}""")
        assertFalse(StrongCustomerAuthentication.requested(TransactionData.entries(request(pwa))))
        assertTrue(StrongCustomerAuthentication.requested(TransactionData.entries(request(pwa, sca("pid")))))
        assertTrue(StrongCustomerAuthentication.isScaType("https://example.org/transaction-data-type/login_risk"))
    }

    @Test
    fun `6_9 transaction data on a credential requested without holder binding is invalid`() {
        assertTrue(invalid { TransactionData.entries(request(sca("pid"), binding = false)) }.contains("holder binding"))
    }

    @Test
    fun `unrecognised types are refused only when the host lists the types it knows`() {
        TransactionData.entries(request(sca("pid")))
        invalid { TransactionData.entries(request(sca("pid")), recognisedTypes = setOf("payment_data")) }
        TransactionData.entries(request(sca("pid")), recognisedTypes = setOf("urn:eudi:sca:payment:1"))
    }

    @Test
    fun `6_12 the resolver carries the typed entries and refuses invalid ones`() {
        val enc = { v: String -> URLEncoder.encode(v, "UTF-8") }
        fun link(data: List<String>) = "openid4vp://?client_id=${enc("redirect_uri:" + VerificationFixtures.RESPONSE_URI)}&nonce=n" +
            "&dcql_query=${enc(Gson().toJson(request().dcqlQuery))}" +
            "&transaction_data=${enc(Gson().toJson(data))}"
        val byValue = runBlocking { PresentationRequestResolver().resolve(link(listOf(sca("pid")))) } as PresentationRequestOutcome.Resolved
        assertEquals("urn:eudi:sca:payment:1", byValue.transactionData.single().type)
        val byValueBad = runBlocking { PresentationRequestResolver().resolve(link(listOf(sca("passport")))) } as PresentationRequestOutcome.Failed
        assertEquals("invalid_transaction_data", byValueBad.error.errorCode)

        val viaObject = runBlocking {
            val jwt = com.nimbusds.jwt.PlainJWT(com.nimbusds.jwt.JWTClaimsSet.Builder()
                .claim("client_id", "redirect_uri:" + VerificationFixtures.RESPONSE_URI).claim("nonce", "n")
                .claim("dcql_query", Gson().fromJson(Gson().toJson(request().dcqlQuery), Map::class.java))
                .claim("transaction_data", listOf(sca("pid"))).build()).serialize()
            PresentationRequestResolver(PresentationRequestPolicy(allowUnsignedRequestObjects = true)).resolve(jwt)
        } as PresentationRequestOutcome.Resolved
        assertEquals("urn:eudi:sca:payment:1", viaObject.transactionData.single().type)

        val bad = runBlocking {
            val jwt = com.nimbusds.jwt.PlainJWT(com.nimbusds.jwt.JWTClaimsSet.Builder()
                .claim("client_id", "redirect_uri:" + VerificationFixtures.RESPONSE_URI).claim("nonce", "n")
                .claim("dcql_query", Gson().fromJson(Gson().toJson(request().dcqlQuery), Map::class.java))
                .claim("transaction_data", listOf(sca("passport"))).build()).serialize()
            PresentationRequestResolver().resolve(jwt)
        } as PresentationRequestOutcome.Failed
        assertEquals("invalid_transaction_data", bad.error.errorCode)
    }

    @Test
    fun `the submitter refuses invalid transaction data with invalid_transaction_data`() {
        val key = VerificationFixtures.key("h")
        val outcome = runBlocking {
            PresentationSubmitter().submit(request(sca("passport")), listOf(SelectedCredential("pid", VerificationFixtures.sdJwt(), key)), WalletIdentity(null, key))
        } as PresentationOutcome.Refused
        assertEquals("invalid_transaction_data", outcome.error.errorCode)
    }
}
