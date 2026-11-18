package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation

import com.ewc.eudi_wallet_oidc_android.models.ErrorCodes
import com.ewc.eudi_wallet_oidc_android.models.KeyAttestationOutcome
import com.ewc.eudi_wallet_oidc_android.models.WalletProviderOutcome
import com.ewc.eudi_wallet_oidc_android.models.WalletUnitRevocationCodeOutcome
import com.ewc.eudi_wallet_oidc_android.models.WalletUnitStatusOutcome
import com.google.gson.JsonParser
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.TimeUnit

class WalletProviderClientTest {

    private lateinit var server: MockWebServer
    private val keys = SoftwareDeviceKeys()
    private val integrity = FakeIntegrity()
    private lateinit var client: WalletProviderClient
    private val clientId = "did:key:unit"

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        client = testClient(server, keys, integrity)
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    private fun take() = server.takeRequest(1, TimeUnit.SECONDS)!!

    private fun wia(code: String? = null) =
        "{\"walletUnitAttestation\":\"wia.jwt\",\"credentialIssuer\":\"https://issuer\"" +
            (code?.let { ",\"revocationCode\":\"$it\"" } ?: "") + "}"

    private fun register(): WalletProviderOutcome<*> {
        server.nonce("n-register")
        server.answer(200, wia("7KQ2 M9XA H4TD 0RWE 5BNC"))
        val outcome = runBlocking { client.requestWalletUnitAttestation(softwareEcKey(), clientId, "ts3") }
        take(); take()
        return outcome
    }

    @Test
    fun theFirstWiaRequestRegistersTheUnit() = runBlocking {
        val cnf = softwareEcKey()
        server.nonce("0lMVydR0KKSM77lW/WGVjqv4kJw=")
        server.answer(200, wia("7KQ2 M9XA H4TD 0RWE 5BNC"))

        val outcome = client.requestWalletUnitAttestation(cnf, clientId, "ts3")

        val nonceRequest = take()
        assertEquals("POST", nonceRequest.method)
        assertEquals("/organisation/1/service/wallet-provider/nonce", nonceRequest.path)
        val request = take()
        assertEquals("/organisation/1/service/wallet-provider/wallet-unit/request", request.path)

        val result = (outcome as WalletProviderOutcome.Success).value
        assertEquals("wia.jwt", result.walletUnitAttestation)
        assertEquals("7KQ2 M9XA H4TD 0RWE 5BNC", result.revocationCode)
        assertEquals("https://issuer", result.credentialIssuer)

        // The device key was made with the nonce as its attestation challenge, and registered.
        val deviceKey = keys.made.single()
        assertEquals(listOf("0lMVydR0KKSM77lW/WGVjqv4kJw="), keys.challenges)
        assertTrue(client.isRegistered)

        // Headers, body, digest and signature.
        val bodyBytes = request.body.readByteArray()
        assertEquals(HTTPMessageSignature.contentDigest(bodyBytes), request.getHeader("Content-Digest"))
        assertEquals("0lMVydR0KKSM77lW/WGVjqv4kJw=", request.getHeader("X-Wallet-Unit-Nonce"))
        assertEquals("android", request.getHeader("X-Wallet-Unit-Platform"))
        assertEquals("2026.12.0", request.getHeader("X-Wallet-App-Version"))
        assertEquals("490", request.getHeader("X-Wallet-App-Build"))
        assertEquals("samsung SM-A125F", request.getHeader("X-Wallet-Device-Model"))
        assertTrue(request.getHeader("Signature-Input")!!.contains("keyid=\"${deviceKey.signing.keyId}\""))
        assertTrue(verifiesRequestSignature(request, deviceKey.signing.publicJwk))

        val binding = BatchRequestHash.requestBinding("0lMVydR0KKSM77lW/WGVjqv4kJw=", listOf(cnf))
        assertEquals("integrity-for-$binding", request.getHeader("X-Wallet-Unit-Integrity-Token"))
        assertTrue(verifiesDeviceSignature(request, binding, deviceKey.signing.publicJwk))

        val body = JsonParser.parseString(String(bodyBytes)).asJsonObject
        assertEquals(WalletProviderClient.CLIENT_ASSERTION_TYPE, body.get("client_assertion_type").asString)
        assertEquals("ts3", body.get("profile").asString)
        assertEquals(listOf("leaf-0", "intermediate", "root"), body.getAsJsonArray("android_key_attestation_x5c").map { it.asString })
        val claims = SignedJWT.parse(body.get("client_assertion").asString).jwtClaimsSet
        assertEquals(clientId, claims.getStringClaim("client_id"))
        assertEquals(client.baseUrl, claims.audience.single())
    }

    @Test
    fun aLaterRequestIsSignedWithTheSameKeyAndSendsNoChain() = runBlocking {
        register()
        val deviceKey = keys.made.single()
        server.nonce("u30M8e5ErKC8wPc5t3uTXxOuwv0=")
        server.answer(200, wia())

        val outcome = client.requestWalletUnitAttestation(softwareEcKey(), clientId, null)

        take()
        val request = take()
        assertTrue(outcome is WalletProviderOutcome.Success)
        assertEquals(1, keys.made.size)
        assertTrue(verifiesRequestSignature(request, deviceKey.signing.publicJwk))
        assertNotNull(request.getHeader("X-Wallet-Unit-Integrity-Token"))
        val body = JsonParser.parseString(request.body.readUtf8()).asJsonObject
        assertFalse(body.has("android_key_attestation_x5c"))
        assertFalse(body.has("profile"))
    }

    @Test
    fun aBatchRegistrationBindsEveryCnfKey() = runBlocking {
        val cnfKeys = List(3) { softwareEcKey() }
        server.nonce("bJsZy5Z7Vj2dlrNBrUqJp0RExvE=")
        server.answer(200, "{\"walletUnitAttestations\":[\"w0\",\"w1\",\"w2\"],\"revocationCode\":\"CODE\"}")

        val outcome = client.requestWalletUnitAttestations(cnfKeys, clientId, "ts3")

        take()
        val request = take()
        assertEquals("/organisation/1/service/wallet-provider/wallet-unit/request/batch", request.path)
        val result = (outcome as WalletProviderOutcome.Success).value
        assertEquals(listOf("w0", "w1", "w2"), result.attestations)
        assertEquals("CODE", result.revocationCode)
        assertEquals(clientId, result.clientId)
        val binding = BatchRequestHash.requestBinding("bJsZy5Z7Vj2dlrNBrUqJp0RExvE=", cnfKeys)
        assertEquals(listOf(binding), integrity.bindings)
        val body = JsonParser.parseString(request.body.readUtf8()).asJsonObject
        assertEquals(3, body.getAsJsonArray("client_assertions").size())
        assertTrue(body.has("android_key_attestation_x5c"))
        assertTrue(client.isRegistered)
    }

    @Test
    fun aStatusReadWithoutEvidenceIsSignedOnly() = runBlocking {
        register()
        server.nonce("SQ9vHYVxaWxajhdOG7Gcja0z1r0=")
        server.answer(200, "{\"status\":\"suspended\",\"reason\":\"wallet_provider\",\"revokedAt\":null,\"deviceCheckDue\":true,\"revocationCodeIssued\":false}")

        val outcome = client.status(withEvidence = false)

        take()
        val request = take()
        assertEquals("/organisation/1/service/wallet-provider/wallet-unit/status", request.path)
        assertEquals("{}", request.body.readUtf8())
        assertNull(request.getHeader("X-Wallet-Unit-Integrity-Token"))
        assertNull(request.getHeader("X-Wallet-Unit-Device-Signature"))
        assertTrue(verifiesRequestSignature(request, keys.made.single().signing.publicJwk))
        val status = (outcome as WalletUnitStatusOutcome.Known).status
        assertTrue(status.isSuspended)
        assertEquals("wallet_provider", status.reason)
        assertTrue(status.deviceCheckDue)
        assertFalse(status.revocationCodeIssued)
    }

    @Test
    fun aStatusReadWithEvidenceBindsNoKeys() = runBlocking {
        register()
        server.nonce("SQ9vHYVxaWxajhdOG7Gcja0z1r0=")
        server.answer(200, "{\"status\":\"active\"}")

        val outcome = client.status(withEvidence = true)

        take()
        val request = take()
        val binding = BatchRequestHash.requestBinding("SQ9vHYVxaWxajhdOG7Gcja0z1r0=", emptyList())
        assertEquals("integrity-for-$binding", request.getHeader("X-Wallet-Unit-Integrity-Token"))
        assertTrue(verifiesDeviceSignature(request, binding, keys.made.single().signing.publicJwk))
        assertTrue((outcome as WalletUnitStatusOutcome.Known).status.isActive)
    }

    @Test
    fun aStatusReadBeforeTheRegistrationSendsNothing() = runBlocking {
        assertEquals(WalletUnitStatusOutcome.NotRegistered, client.status(withEvidence = true))
        assertEquals(0, server.requestCount)
    }

    @Test
    fun unitNotFoundForgetsTheRegistration() = runBlocking {
        register()
        server.nonce("n")
        server.answer(404, refusal("unit_not_found"))

        assertEquals(WalletUnitStatusOutcome.NotRegistered, client.status(withEvidence = false))
        assertFalse(client.isRegistered)
        assertFalse(client.isKeyLost)
    }

    @Test
    fun aServerWithoutProtocol2IsNotSupported() = runBlocking {
        register()
        server.nonce("n")
        server.answer(404, "{\"detail\":\"Not Found\"}")
        assertEquals(WalletUnitStatusOutcome.NotSupported, client.status(withEvidence = false))
    }

    @Test
    fun aRevokedRefusalOfTheStatusReadIsTheRevokedStatus() = runBlocking {
        register()
        server.nonce("n")
        server.answer(403, refusal("revoked", "user_request"))
        val status = (client.status(withEvidence = false) as WalletUnitStatusOutcome.Known).status
        assertTrue(status.isRevoked)
        assertEquals("user_request", status.reason)
    }

    @Test
    fun aRefusalCarriesTheErrorIdReasonAndStatus() = runBlocking {
        server.nonce("n")
        server.answer(403, refusal("device_refused", "patch_level_too_old"))

        val error = (client.requestWalletUnitAttestation(softwareEcKey(), clientId, null) as WalletProviderOutcome.Failed).error

        assertEquals(WalletProviderErrorId.DEVICE_REFUSED, error.errorId)
        assertEquals("patch_level_too_old", error.reason)
        assertEquals(403, error.httpStatus)
        assertFalse(client.isRegistered)
        assertEquals(listOf("software_0"), keys.discarded)
    }

    @Test
    fun aRefusedSignatureIsSentOnceMoreWithANewNonce() = runBlocking {
        server.nonce("n1")
        server.answer(401, refusal("request_signature_invalid"))
        server.nonce("n2")
        server.answer(200, wia("CODE"))

        val outcome = client.requestWalletUnitAttestation(softwareEcKey(), clientId, null)

        assertTrue(outcome is WalletProviderOutcome.Success)
        assertEquals(4, server.requestCount)
        // A registration key carries its nonce as challenge, so the retry made a new one.
        assertEquals(listOf("n1", "n2"), keys.challenges)
        assertEquals("software_1", keys.registered()?.alias)
    }

    @Test
    fun aSecondRefusedSignatureGoesToTheApp() = runBlocking {
        repeat(2) {
            server.nonce("n$it")
            server.answer(401, refusal("request_signature_invalid"))
        }
        val error = (client.requestWalletUnitAttestation(softwareEcKey(), clientId, null) as WalletProviderOutcome.Failed).error
        assertEquals("individual_wallet_unit.request_signature_invalid", error.errorId)
        assertEquals(4, server.requestCount)
    }

    @Test
    fun deviceRegisteredBeforeSendsAgainAsARegisteredUnit() = runBlocking {
        server.nonce("n1")
        server.answer(400, refusal("device_registered_before"))
        server.nonce("n2")
        server.answer(200, wia())

        val outcome = client.requestWalletUnitAttestation(softwareEcKey(), clientId, null)

        take(); take(); take()
        val resent = take()
        assertTrue(outcome is WalletProviderOutcome.Success)
        assertTrue(client.isRegistered)
        assertEquals(1, keys.made.size)
        assertFalse(JsonParser.parseString(resent.body.readUtf8()).asJsonObject.has("android_key_attestation_x5c"))
    }

    @Test
    fun aRegistrationWhoseAnswerWasLostIsTheKeyTheProviderKnows() = runBlocking {
        server.nonce("n1")
        server.enqueue(okhttp3.mockwebserver.MockResponse().setSocketPolicy(okhttp3.mockwebserver.SocketPolicy.DISCONNECT_AFTER_REQUEST))
        val lost = client.requestWalletUnitAttestation(softwareEcKey(), clientId, null)
        assertEquals(ErrorCodes.WALLET_PROVIDER_UNREACHABLE, (lost as WalletProviderOutcome.Failed).error.error)
        assertFalse(client.isRegistered)

        server.nonce("n2")
        server.answer(400, refusal("device_registered_before"))
        server.nonce("n3")
        server.answer(200, wia())
        val outcome = client.requestWalletUnitAttestation(softwareEcKey(), clientId, null)

        assertTrue(outcome is WalletProviderOutcome.Success)
        assertEquals("software_0", keys.registered()?.alias)
    }

    @Test
    fun requestKeyInUseRegistersWithANewDeviceKey() = runBlocking {
        server.nonce("n1")
        server.answer(409, refusal("request_key_in_use"))
        server.nonce("n2")
        server.answer(200, wia())

        assertTrue(client.requestWalletUnitAttestation(softwareEcKey(), clientId, null) is WalletProviderOutcome.Success)
        assertEquals(2, keys.made.size)
        assertEquals("software_1", keys.registered()?.alias)
    }

    @Test
    fun deviceKeyAttestationMissingRegistersAgain() = runBlocking {
        register()
        server.nonce("n1")
        server.answer(400, refusal("device_key_attestation_missing"))
        server.nonce("n2")
        server.answer(200, wia("NEW"))

        val outcome = client.requestWalletUnitAttestation(softwareEcKey(), clientId, null)

        assertEquals("NEW", (outcome as WalletProviderOutcome.Success).value.revocationCode)
        assertEquals(2, keys.made.size)
        assertEquals("software_1", keys.registered()?.alias)
        assertEquals("n2", keys.challenges.last())
    }

    @Test
    fun registeredOnOtherDeviceGoesToTheApp() = runBlocking {
        server.nonce("n")
        server.answer(409, refusal("registered_on_other_device"))
        val error = (client.requestWalletUnitAttestation(softwareEcKey(), clientId, null) as WalletProviderOutcome.Failed).error
        assertEquals(WalletProviderErrorId.REGISTERED_ON_OTHER_DEVICE, error.errorId)
        assertEquals(409, error.httpStatus)
    }

    @Test
    fun noNonceSendsNothing() = runBlocking {
        server.answer(200, "{\"c_nonce\":\"\"}")
        val error = (client.requestWalletUnitAttestation(softwareEcKey(), clientId, null) as WalletProviderOutcome.Failed).error
        assertEquals(ErrorCodes.WALLET_PROVIDER_REQUEST_FAILED, error.error)
        assertEquals(1, server.requestCount)
        assertTrue(keys.made.isEmpty())
    }

    @Test
    fun aPlayIntegrityFailureSendsNothing() = runBlocking {
        integrity.failure = IllegalStateException("PLAY_SERVICES_NOT_FOUND")
        server.nonce("n")
        val error = (client.requestWalletUnitAttestation(softwareEcKey(), clientId, null) as WalletProviderOutcome.Failed).error
        assertEquals(ErrorCodes.WALLET_PROVIDER_REQUEST_FAILED, error.error)
        assertEquals(1, server.requestCount)
        assertEquals(listOf("software_0"), keys.discarded)
    }

    @Test
    fun aLostDeviceKeyIsReportedAndSendsNothing() = runBlocking {
        register()
        keys.loseKey()
        assertTrue(client.isKeyLost)
        val before = server.requestCount
        val error = (client.requestWalletUnitAttestation(softwareEcKey(), clientId, null) as WalletProviderOutcome.Failed).error
        assertEquals(ErrorCodes.WALLET_UNIT_KEY_LOST, error.error)
        val status = client.status(withEvidence = false) as WalletUnitStatusOutcome.Failed
        assertEquals(ErrorCodes.WALLET_UNIT_KEY_LOST, status.error.error)
        assertEquals(before, server.requestCount)
    }

    @Test
    fun resetMakesTheNextRequestARegistration() = runBlocking {
        register()
        client.reset()
        assertFalse(client.isRegistered)
        assertFalse(client.isKeyLost)
        server.nonce("n")
        server.answer(200, wia("NEW"))
        assertEquals("NEW", (client.requestWalletUnitAttestation(softwareEcKey(), clientId, null) as WalletProviderOutcome.Success).value.revocationCode)
        assertEquals(2, keys.made.size)
    }

    @Test
    fun twoConcurrentRequestsMakeOneRegistration() = runBlocking {
        server.nonce("n1")
        server.answer(200, wia("CODE"))
        server.nonce("n2")
        server.answer(200, wia())

        val first = async { client.requestWalletUnitAttestation(softwareEcKey(), clientId, null) }
        val second = async { client.requestWalletUnitAttestation(softwareEcKey(), clientId, null) }
        assertTrue(first.await() is WalletProviderOutcome.Success)
        assertTrue(second.await() is WalletProviderOutcome.Success)

        assertEquals(1, keys.made.size)
        val chains = (0 until 4).map { take() }
            .filter { it.path!!.endsWith("/wallet-unit/request") }
            .count { JsonParser.parseString(it.body.readUtf8()).asJsonObject.has("android_key_attestation_x5c") }
        assertEquals(1, chains)
    }

    @Test
    fun theRevocationCodeIsIssuedWithoutEvidence() = runBlocking {
        register()
        server.nonce("4jM4NlThNJBmEK1UJI8vimYtU1c=")
        server.answer(201, "{\"revocationCode\":\"Q8ZD 2MXK 7HTA W0RN 5CEB\"}")

        val outcome = client.revocationCode()

        take()
        val request = take()
        assertEquals("/organisation/1/service/wallet-provider/wallet-unit/revocation-code", request.path)
        assertNull(request.getHeader("X-Wallet-Unit-Integrity-Token"))
        assertTrue(verifiesRequestSignature(request, keys.made.single().signing.publicJwk))
        assertEquals("Q8ZD 2MXK 7HTA W0RN 5CEB", (outcome as WalletUnitRevocationCodeOutcome.Issued).code)
        assertFalse(outcome.toString().contains("Q8ZD"))
    }

    @Test
    fun anExistingRevocationCodeIsAlreadyIssued() = runBlocking {
        register()
        server.nonce("n")
        server.answer(409, refusal("revocation_code_exists"))
        assertEquals(WalletUnitRevocationCodeOutcome.AlreadyIssued, client.revocationCode())
    }

    @Test
    fun keyAttestationOfARegisteredUnitIsSignedWithTheIssuerNonce() = runBlocking {
        register()
        val attested = List(2) { softwareEcKey() }
        server.answer(200, "{\"keyAttestation\":\"ka.jwt\",\"attestationType\":\"android_keystore\",\"keyStorage\":[],\"attestedKeysCount\":2}")

        val outcome: KeyAttestationOutcome = KeyAttestationService.requestBatchKeyAttestation(
            baseUrl = "ignored for protocol 2",
            walletUnitAttestationJWT = "wia.jwt~",
            walletUnitProofOfPossession = "pop.jwt",
            nonce = "issuer-c-nonce-3f9a1b7c",
            attestedKeys = attested,
            androidKeyAttestationX5cChains = listOf(listOf("a"), listOf("b")),
            walletProvider = client
        )

        val request = take()
        assertEquals("/organisation/1/service/wallet-provider/key-attestation", request.path)
        assertEquals("issuer-c-nonce-3f9a1b7c", request.getHeader("X-Wallet-Unit-Nonce"))
        assertEquals("wia.jwt", request.getHeader("OAuth-Client-Attestation"))
        assertEquals("pop.jwt", request.getHeader("OAuth-Client-Attestation-PoP"))
        val binding = BatchRequestHash.requestBinding("issuer-c-nonce-3f9a1b7c", attested)
        assertEquals("integrity-for-$binding", request.getHeader("X-Wallet-Unit-Integrity-Token"))
        assertTrue(verifiesRequestSignature(request, keys.made.single().signing.publicJwk))
        val body = JsonParser.parseString(request.body.readUtf8()).asJsonObject
        assertEquals(2, body.getAsJsonArray("attested_keys").size())
        assertEquals(2, body.getAsJsonArray("android_key_attestation_x5c").size())
        assertTrue(outcome.isSuccessful)
        assertEquals("ka.jwt", outcome.response?.keyAttestation)
    }

    @Test
    fun aRefusedKeyAttestationKeepsTheErrorId() = runBlocking {
        register()
        server.answer(403, refusal("suspended", "wallet_provider"))
        val outcome = KeyAttestationService.requestBatchKeyAttestation(
            baseUrl = "x", walletUnitAttestationJWT = "w", walletUnitProofOfPossession = "p",
            nonce = "c", attestedKeys = listOf(softwareEcKey()), walletProvider = client
        )
        assertFalse(outcome.isSuccessful)
        assertEquals(403, outcome.httpCode)
        assertEquals(WalletProviderErrorId.SUSPENDED, outcome.error?.errorId)
        // The issuer nonce cannot be renewed here: one request, no retry.
        assertEquals(3, server.requestCount)
    }
}
