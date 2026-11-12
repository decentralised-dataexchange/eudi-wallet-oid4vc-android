package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.protocol2

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.Signature
import java.util.Base64

/**
 * The protocol 2 client against a fake wallet provider: the registration of the device key, the
 * evidence, the signature headers, the retry with a new nonce, the error mapping, the status and
 * revocation code logic and the compatibility with a wallet provider of protocol 1.
 */
class WalletProviderClientTest {

    private val base = "https://wallet.example/organisation/6ae0f1a2/service/wallet-provider"

    // ---- fakes ----

    private class FakeKeys : WalletUnitRequestKeyStore {
        var registered: AttestedRequestKey? = null
        val made = mutableListOf<Pair<ByteArray, AttestedRequestKey>>()
        val discarded = mutableListOf<AttestedRequestKey>()
        var forgotten = 0

        override fun registeredKey(): WalletUnitRequestKey? = registered?.key
        override fun newAttestedKey(challenge: ByteArray): AttestedRequestKey {
            val key = AttestedRequestKey(
                PrivateKeyRequestKey.of(ECKeyGenerator(Curve.P_256).generate()),
                listOf("bGVhZg==", "cm9vdA==")
            )
            made += challenge to key
            return key
        }
        override fun markRegistered(key: AttestedRequestKey) { registered = key }
        override fun discard(key: AttestedRequestKey) { discarded += key }
        override fun forgetRegistered() { registered = null; forgotten++ }
    }

    private class Sent(val url: String, val headers: Map<String, String>, val body: String)

    private class FakeServer(val answers: MutableList<HttpAnswer>) : WalletProviderTransport {
        val sent = mutableListOf<Sent>()
        var nonces = 0
        var nonceAnswer: (Int) -> HttpAnswer = { HttpAnswer(200, "{\"nonce\":\"n-$it\",\"c_nonce\":\"c-$it\"}") }

        override suspend fun get(url: String): HttpAnswer = nonceAnswer(++nonces)
        override suspend fun post(url: String, headers: Map<String, String>, body: ByteArray): HttpAnswer {
            sent += Sent(url, headers, String(body, Charsets.UTF_8))
            return answers.removeAt(0)
        }
    }

    private val bindings = mutableListOf<String>()
    private val integrity = IntegrityTokenSource { binding -> bindings += binding; "token-for-$binding" }
    private val app = WalletAppIdentity("2026.12.0", "490", "samsung SM-A125F")

    private fun client(server: FakeServer, keys: FakeKeys, source: IntegrityTokenSource = integrity) =
        WalletProviderClient(base, app, keys, source, server, clock = { 1794556800L })

    private val cnfKey: ECKey = ECKeyGenerator(Curve.P_256).generate()

    private fun verifiesDer(key: WalletUnitRequestKey, data: String, derBase64Url: String): Boolean =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(key.publicJwk.toECPublicKey())
            update(data.toByteArray(Charsets.UTF_8))
            verify(Base64.getUrlDecoder().decode(derBase64Url))
        }

    private fun signatureVerifies(sent: Sent, key: WalletUnitRequestKey): Boolean {
        val params = sent.headers.getValue("Signature-Input").removePrefix("wp=")
        val base = HttpMessageSignature.signatureBase(
            "POST", sent.url, sent.headers, Protocol2Headers.ANDROID_COMPONENTS, params
        )
        val raw = sent.headers.getValue("Signature").removePrefix("wp=:").removeSuffix(":")
        return HttpMessageSignature.verify(base, raw, key.publicJwk)
    }

    // ---- base URL ----

    @Test
    fun `both resolved base forms give the wallet provider base`() {
        val service = "https://h/organisation/o/service"
        assertEquals("$service/wallet-provider", WalletProviderClient.walletProviderBase(service))
        assertEquals("$service/wallet-provider", WalletProviderClient.walletProviderBase("$service/"))
        assertEquals("$service/wallet-provider", WalletProviderClient.walletProviderBase("$service/wallet-provider"))
        assertEquals("$service/wallet-provider", WalletProviderClient.walletProviderBase("$service/wallet-provider/"))
    }

    // ---- WIA request ----

    @Test
    fun `the first WIA request registers a new device key with the nonce as challenge`() = runBlocking {
        val server = FakeServer(mutableListOf(
            HttpAnswer(200, "{\"walletUnitAttestation\":\"wia\",\"credentialIssuer\":\"iss\",\"revocationCode\":\"ABCD EFGH JKMN PQRS TVWX\"}")
        ))
        val keys = FakeKeys()
        val outcome = client(server, keys).requestWalletUnitAttestation(cnfKey, "did:key:z1", profile = "ts3")

        assertTrue(outcome.isSuccess)
        assertEquals("wia", outcome.value!!.walletUnitAttestation)
        assertEquals("ABCD EFGH JKMN PQRS TVWX", outcome.value!!.revocationCode)
        val (challenge, attested) = keys.made.single()
        assertEquals("n-1", String(challenge, Charsets.UTF_8))
        assertSame(attested, keys.registered)

        val sent = server.sent.single()
        assertEquals("$base/wallet-unit/request", sent.url)
        val body = JSONObject(sent.body)
        assertEquals(listOf("bGVhZg==", "cm9vdA=="), (0 until 2).map { body.getJSONArray("android_key_attestation_x5c").getString(it) })
        assertEquals("ts3", body.getString("profile"))
        assertEquals(WalletProviderClient.CLIENT_ASSERTION_TYPE, body.getString("client_assertion_type"))
        assertEquals(outcome.value!!.clientAssertion, body.getString("client_assertion"))

        // Evidence: the classic token over the request binding, the device signature over it.
        val binding = RequestBinding.of("n-1", listOf(cnfKey))
        assertEquals(listOf(binding), bindings)
        assertEquals("token-for-$binding", sent.headers["X-Wallet-Unit-Integrity-Token"])
        assertTrue(verifiesDer(attested.key, binding, sent.headers.getValue("X-Wallet-Unit-Device-Signature")))

        // The statements and the signature.
        assertEquals("application/json", sent.headers["Content-Type"])
        assertEquals(ContentDigest.sha256(sent.body.toByteArray()), sent.headers["Content-Digest"])
        assertEquals("n-1", sent.headers["X-Wallet-Unit-Nonce"])
        assertEquals("android", sent.headers["X-Wallet-Unit-Platform"])
        assertEquals("2026.12.0", sent.headers["X-Wallet-App-Version"])
        assertEquals("490", sent.headers["X-Wallet-App-Build"])
        assertEquals("samsung SM-A125F", sent.headers["X-Wallet-Device-Model"])
        assertTrue(sent.headers.getValue("Signature-Input").contains("keyid=\"${attested.key.keyId}\""))
        assertTrue(signatureVerifies(sent, attested.key))
    }

    @Test
    fun `a registered unit signs with its key and sends no chain`() = runBlocking {
        val server = FakeServer(mutableListOf(HttpAnswer(200, "{\"walletUnitAttestation\":\"wia\"}")))
        val keys = FakeKeys().apply { registered = newAttestedKey(ByteArray(1)); made.clear() }
        client(server, keys).requestWalletUnitAttestation(cnfKey, "did:key:z1")

        assertTrue(keys.made.isEmpty())
        val sent = server.sent.single()
        assertFalse(JSONObject(sent.body).has("android_key_attestation_x5c"))
        assertFalse(JSONObject(sent.body).has("profile"))
        assertTrue(signatureVerifies(sent, keys.registered!!.key))
    }

    @Test
    fun `request_signature_invalid is sent again once with a new nonce`() = runBlocking {
        val invalid = HttpAnswer(401, "{\"error\":\"invalid_request\",\"error_id\":\"individual_wallet_unit.request_signature_invalid\"}")
        val server = FakeServer(mutableListOf(invalid, HttpAnswer(200, "{\"walletUnitAttestation\":\"wia\"}")))
        val keys = FakeKeys()
        val outcome = client(server, keys).requestWalletUnitAttestation(cnfKey, "did:key:z1")

        assertTrue(outcome.isSuccess)
        assertEquals(listOf("n-1", "n-2"), server.sent.map { it.headers["X-Wallet-Unit-Nonce"] })
        // The first attested key is deleted, the second is the registered key.
        assertEquals(2, keys.made.size)
        assertEquals(listOf(keys.made[0].second), keys.discarded)
        assertSame(keys.made[1].second, keys.registered)
    }

    @Test
    fun `a second request_signature_invalid is a general error`() = runBlocking {
        val invalid = HttpAnswer(401, "{\"error_id\":\"individual_wallet_unit.request_signature_invalid\"}")
        val server = FakeServer(mutableListOf(invalid, invalid))
        val keys = FakeKeys()
        val outcome = client(server, keys).requestWalletUnitAttestation(cnfKey, "did:key:z1")

        assertFalse(outcome.isSuccess)
        assertEquals(2, server.sent.size)
        assertEquals(WalletProviderErrorAction.RETRY_WITH_NEW_NONCE, outcome.error!!.action)
        assertNull(keys.registered)
    }

    @Test
    fun `an error answer gives the error and no retry`() = runBlocking {
        val server = FakeServer(mutableListOf(
            HttpAnswer(403, "{\"error\":\"access_denied\",\"error_id\":\"individual_wallet_unit.device_refused\",\"reason\":\"device_class_vulnerable\"}")
        ))
        val keys = FakeKeys()
        val outcome = client(server, keys).requestWalletUnitAttestation(cnfKey, "did:key:z1")

        assertEquals(1, server.sent.size)
        assertEquals(WalletProviderErrorAction.DEVICE_REFUSED, outcome.error!!.action)
        assertEquals("device_class_vulnerable", outcome.error!!.reason)
        assertNull(keys.registered)
        assertEquals(1, keys.discarded.size)
    }

    @Test
    fun `registered_on_other_device is not retried and deletes the new device key`() = runBlocking {
        val server = FakeServer(mutableListOf(
            HttpAnswer(409, "{\"error\":\"invalid_request\",\"error_id\":\"individual_wallet_unit.registered_on_other_device\"}")
        ))
        val keys = FakeKeys()
        val outcome = client(server, keys).requestWalletUnitAttestation(cnfKey, "did:key:z1")

        assertEquals(1, server.sent.size)
        assertEquals(WalletProviderErrorAction.START_NEW_UNIT, outcome.error!!.action)
        assertEquals(409, outcome.error!!.httpCode)
        assertNull(keys.registered)
        assertEquals(listOf(keys.made.single().second), keys.discarded)
    }

    @Test
    fun `without a Play Integrity token no WIA request goes`() = runBlocking {
        val server = FakeServer(mutableListOf())
        val keys = FakeKeys()
        val outcome = client(server, keys, IntegrityTokenSource { null })
            .requestWalletUnitAttestation(cnfKey, "did:key:z1")

        assertFalse(outcome.isSuccess)
        assertTrue(outcome.error!!.isTransport)
        assertTrue(server.sent.isEmpty())
        assertEquals(1, keys.discarded.size)
    }

    @Test
    fun `the nonce falls back to c_nonce`() = runBlocking {
        val server = FakeServer(mutableListOf()).apply { nonceAnswer = { HttpAnswer(200, "{\"c_nonce\":\"only-c\"}") } }
        assertEquals("only-c", client(server, FakeKeys()).nonce())
    }

    @Test
    fun `the batch request binds all cnf keys and sends one assertion for each`() = runBlocking {
        val server = FakeServer(mutableListOf(HttpAnswer(200, "{\"walletUnitAttestations\":[\"a\",\"b\"]}")))
        val keys = FakeKeys()
        val second = ECKeyGenerator(Curve.P_256).generate()
        val outcome = client(server, keys).requestWalletUnitAttestations(listOf(cnfKey, second), "did:key:z1")

        assertEquals(listOf("a", "b"), outcome.value!!.walletUnitAttestations)
        val sent = server.sent.single()
        assertEquals("$base/wallet-unit/request/batch", sent.url)
        assertEquals(2, JSONObject(sent.body).getJSONArray("client_assertions").length())
        assertTrue(JSONObject(sent.body).has("android_key_attestation_x5c"))
        assertEquals(listOf(RequestBinding.of("n-1", listOf(second, cnfKey))), bindings)
    }

    // ---- status ----

    @Test
    fun `status without a registered key asks for the registration and sends nothing`() = runBlocking {
        val server = FakeServer(mutableListOf())
        assertSame(WalletUnitStatusResult.NotRegistered, client(server, FakeKeys()).status(withEvidence = true))
        assertTrue(server.sent.isEmpty())
    }

    @Test
    fun `status with evidence binds the empty set of cnf keys`() = runBlocking {
        val server = FakeServer(mutableListOf(HttpAnswer(200,
            "{\"status\":\"active\",\"reason\":null,\"revokedAt\":null,\"deviceCheckDue\":false,\"revocationCodeIssued\":false}"
        )))
        val keys = FakeKeys().apply { registered = newAttestedKey(ByteArray(1)) }
        val result = client(server, keys).status(withEvidence = true)

        val status = (result as WalletUnitStatusResult.Known).status
        assertTrue(status.isActive)
        assertFalse(status.revocationCodeIssued)
        val sent = server.sent.single()
        assertEquals("$base/wallet-unit/status", sent.url)
        assertEquals("{}", sent.body)
        val binding = RequestBinding.of("n-1", emptyList())
        assertEquals("token-for-$binding", sent.headers["X-Wallet-Unit-Integrity-Token"])
        assertTrue(verifiesDer(keys.registered!!.key, binding, sent.headers.getValue("X-Wallet-Unit-Device-Signature")))
        assertTrue(signatureVerifies(sent, keys.registered!!.key))
    }

    @Test
    fun `status without evidence has no evidence headers`() = runBlocking {
        val server = FakeServer(mutableListOf(HttpAnswer(200, "{\"status\":\"suspended\",\"reason\":\"wallet_provider\"}")))
        val keys = FakeKeys().apply { registered = newAttestedKey(ByteArray(1)) }
        val result = client(server, keys).status(withEvidence = false)

        assertTrue((result as WalletUnitStatusResult.Known).status.isSuspended)
        assertEquals("wallet_provider", result.status.reason)
        assertFalse(server.sent.single().headers.containsKey("X-Wallet-Unit-Integrity-Token"))
        assertFalse(server.sent.single().headers.containsKey("X-Wallet-Unit-Device-Signature"))
        assertTrue(bindings.isEmpty())
    }

    @Test
    fun `a wallet provider of protocol 1 gives no status and keeps the key`() = runBlocking {
        val server = FakeServer(mutableListOf(HttpAnswer(404, "{\"detail\":\"Not Found\"}")))
        val keys = FakeKeys().apply { registered = newAttestedKey(ByteArray(1)) }
        assertSame(WalletUnitStatusResult.NotSupported, client(server, keys).status(withEvidence = false))
        assertNotNull(keys.registered)
    }

    @Test
    fun `unit_not_found forgets the registered key`() = runBlocking {
        val server = FakeServer(mutableListOf(HttpAnswer(404, "{\"error_id\":\"individual_wallet_unit.unit_not_found\"}")))
        val keys = FakeKeys().apply { registered = newAttestedKey(ByteArray(1)) }
        assertSame(WalletUnitStatusResult.NotRegistered, client(server, keys).status(withEvidence = false))
        assertNull(keys.registered)
        assertEquals(1, keys.forgotten)
    }

    @Test
    fun `status answers map to results`() {
        val revoked = WalletUnitStatusResult.fromAnswer(403, "{\"error_id\":\"individual_wallet_unit.revoked\",\"reason\":\"user_request\"}")
        assertTrue((revoked as WalletUnitStatusResult.Known).status.isRevoked)
        assertEquals("user_request", revoked.status.reason)
        val suspended = WalletUnitStatusResult.fromAnswer(403, "{\"error_id\":\"individual_wallet_unit.suspended\"}")
        assertTrue((suspended as WalletUnitStatusResult.Known).status.isSuspended)
        val failed = WalletUnitStatusResult.fromAnswer(500, "oops")
        assertEquals(WalletProviderErrorAction.GENERAL, (failed as WalletUnitStatusResult.Failed).error.action)
        assertTrue(WalletUnitStatusResult.fromAnswer(200, "{\"no\":1}") is WalletUnitStatusResult.Failed)
        val missing = WalletUnitStatus.parse("{\"status\":\"revoked\",\"revokedAt\":\"2026-11-13T10:00:00Z\"}")!!
        assertTrue(missing.revocationCodeIssued)
        assertFalse(missing.deviceCheckDue)
        assertEquals("2026-11-13T10:00:00Z", missing.revokedAt)
    }

    // ---- revocation code ----

    @Test
    fun `revocation code results`() = runBlocking {
        val keys = FakeKeys().apply { registered = newAttestedKey(ByteArray(1)) }
        val issued = client(FakeServer(mutableListOf(HttpAnswer(201, "{\"revocationCode\":\"ABCD EFGH JKMN PQRS TVWX\"}"))), keys)
            .revocationCode()
        assertEquals("ABCD EFGH JKMN PQRS TVWX", (issued as WalletProviderClient.RevocationCodeResult.Issued).revocationCode)
        val exists = client(FakeServer(mutableListOf(HttpAnswer(409, "{\"error_id\":\"individual_wallet_unit.revocation_code_exists\"}"))), keys)
            .revocationCode()
        assertSame(WalletProviderClient.RevocationCodeResult.AlreadyIssued, exists)
        val old = client(FakeServer(mutableListOf(HttpAnswer(404, "{\"detail\":\"Not Found\"}"))), keys).revocationCode()
        assertSame(WalletProviderClient.RevocationCodeResult.NotSupported, old)
        val none = client(FakeServer(mutableListOf()), FakeKeys()).revocationCode()
        assertSame(WalletProviderClient.RevocationCodeResult.NotSupported, none)
    }

    // ---- key attestation ----

    @Test
    fun `key attestation headers use the c_nonce and bind the attested keys`() = runBlocking {
        val keys = FakeKeys().apply { registered = newAttestedKey(ByteArray(1)) }
        val server = FakeServer(mutableListOf())
        val attested = ECKeyGenerator(Curve.P_256).generate().toPublicJWK()
        val url = "https://wallet.example/organisation/6ae0f1a2/service/wallet-provider/key-attestation"
        val headers = client(server, keys).keyAttestationHeaders(url, "{\"a\":1}".toByteArray(), "c-nonce", listOf(attested))!!

        assertEquals("c-nonce", headers["X-Wallet-Unit-Nonce"])
        val binding = RequestBinding.of("c-nonce", listOf(attested))
        assertEquals("token-for-$binding", headers["X-Wallet-Unit-Integrity-Token"])
        assertTrue(signatureVerifies(Sent(url, headers, "{\"a\":1}"), keys.registered!!.key))
        assertNull(client(server, FakeKeys()).keyAttestationHeaders(url, ByteArray(0), "c", listOf(attested)))
    }
}
