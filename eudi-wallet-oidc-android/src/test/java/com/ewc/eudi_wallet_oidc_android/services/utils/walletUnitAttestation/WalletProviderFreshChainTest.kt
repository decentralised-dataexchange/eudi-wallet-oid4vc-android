package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation

import com.ewc.eudi_wallet_oidc_android.models.WalletProviderOutcome
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.TimeUnit

/**
 * A later WIA request sends a fresh Key Attestation chain when the last
 * accepted chain of the device is older than [WalletProviderClient.CHAIN_DUE_AFTER_SECONDS].
 */
class WalletProviderFreshChainTest {

    private lateinit var server: MockWebServer
    private val keys = SoftwareDeviceKeys()
    private var now = 1794556800L
    private lateinit var client: WalletProviderClient
    private val clientId = "did:key:unit"
    private val due = WalletProviderClient.CHAIN_DUE_AFTER_SECONDS

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        client = testClient(server, keys, clock = { now })
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    private fun take(): RecordedRequest = server.takeRequest(1, TimeUnit.SECONDS)!!

    private fun RecordedRequest.json(): JsonObject = JsonParser.parseString(body.readUtf8()).asJsonObject

    private fun JsonObject.chain(): List<String>? =
        getAsJsonArray("android_key_attestation_x5c")?.map { it.asString }

    private val wia = "{\"walletUnitAttestation\":\"wia.jwt\"}"

    private fun register() {
        server.nonce("n-register")
        server.answer(200, "{\"walletUnitAttestation\":\"wia.jwt\",\"revocationCode\":\"CODE\"}")
        runBlocking { client.requestWalletUnitAttestation(softwareEcKey(), clientId, null) }
        take(); take()
    }

    private fun requestWia() = runBlocking { client.requestWalletUnitAttestation(softwareEcKey(), clientId, null) }

    @Test
    fun theRegistrationStoresTheTimeOfItsChain() {
        register()
        assertEquals(now, keys.chainAcceptedAt)
    }

    @Test
    fun noChainBeforeItIsDue() {
        register()
        now += due - 1
        server.nonce("n1")
        server.answer(200, wia)

        assertTrue(requestWia() is WalletProviderOutcome.Success)

        take()
        assertNull(take().json().chain())
        assertEquals(1, keys.made.size)
    }

    @Test
    fun aDueChainComesFromANewKeyWithTheNonceAndTheRequestStaysSignedByTheDeviceKey() {
        register()
        val deviceKey = keys.made.single()
        now += due
        server.nonce("n-fresh")
        server.answer(200, wia)

        assertTrue(requestWia() is WalletProviderOutcome.Success)

        take()
        val request = take()
        val chainKey = keys.made[1]
        assertEquals("n-fresh", keys.challenges[1])
        assertEquals(listOf("leaf-1", "intermediate", "root"), request.json().chain())
        assertTrue(verifiesRequestSignature(request, deviceKey.signing.publicJwk))
        // The chain key is deleted, the unit keeps its device key, the time moves on.
        assertEquals(listOf(chainKey.alias), keys.discarded)
        assertEquals(deviceKey, keys.registered())
        assertEquals(now, keys.chainAcceptedAt)
    }

    @Test
    fun anUnknownTimeSendsAChain() {
        register()
        keys.chainAcceptedAt = null // an install from before the timer
        server.nonce("n1")
        server.answer(200, wia)

        requestWia()

        take()
        assertEquals(listOf("leaf-1", "intermediate", "root"), take().json().chain())
    }

    @Test
    fun aBatchRequestSendsADueChain() = runBlocking {
        register()
        now += due
        server.nonce("n-batch")
        server.answer(200, "{\"walletUnitAttestations\":[\"w0\",\"w1\"]}")

        val outcome = client.requestWalletUnitAttestations(List(2) { softwareEcKey() }, clientId, null)

        assertTrue(outcome is WalletProviderOutcome.Success)
        take()
        assertEquals(listOf("leaf-1", "intermediate", "root"), take().json().chain())
        assertEquals(listOf("n-register", "n-batch"), keys.challenges)
    }

    @Test
    fun attestationDueIsSentAgainOnceWithANewNonceAndAChain() {
        register()
        server.nonce("n1")
        server.answer(400, refusal("device_attestation_due"))
        server.nonce("n2")
        server.answer(200, wia)

        assertTrue(requestWia() is WalletProviderOutcome.Success)

        take()
        assertNull(take().json().chain())
        take()
        val retry = take()
        assertEquals("n2", retry.getHeader("X-Wallet-Unit-Nonce"))
        assertEquals("n2", keys.challenges[1])
        assertEquals(listOf("leaf-1", "intermediate", "root"), retry.json().chain())
        assertEquals(now, keys.chainAcceptedAt)
    }

    @Test
    fun attestationDueIsSentAgainOnlyOnce() {
        register()
        server.nonce("n1")
        server.answer(400, refusal("device_attestation_due"))
        server.nonce("n2")
        server.answer(400, refusal("device_attestation_due"))

        val outcome = requestWia()

        assertEquals(
            WalletProviderErrorId.DEVICE_ATTESTATION_DUE,
            (outcome as WalletProviderOutcome.Failed).error.errorId
        )
        assertEquals(6, server.requestCount)
    }

    @Test
    fun aRefusedFreshChainKeepsTheOldTimeAndDeletesTheChainKey() {
        register()
        val registeredAt = now
        now += due
        server.nonce("n1")
        server.answer(403, refusal("device_refused", "patch_level_too_old"))

        val outcome = requestWia()

        val error = (outcome as WalletProviderOutcome.Failed).error
        assertEquals(WalletProviderErrorId.DEVICE_REFUSED, error.errorId)
        assertEquals("patch_level_too_old", error.reason)
        assertEquals(listOf(keys.made[1].alias), keys.discarded)
        assertEquals(registeredAt, keys.chainAcceptedAt)
        assertTrue(client.isRegistered)
    }

    @Test
    fun aNewNonceAfterABadSignatureMakesANewChainKey() {
        register()
        now += due
        server.nonce("n1")
        server.answer(401, refusal("request_signature_invalid"))
        server.nonce("n2")
        server.answer(200, wia)

        assertTrue(requestWia() is WalletProviderOutcome.Success)

        assertEquals(listOf("n-register", "n1", "n2"), keys.challenges)
        assertEquals(listOf(keys.made[1].alias, keys.made[2].alias), keys.discarded)
    }

    @Test
    fun theStatusRouteSendsNoChain() = runBlocking {
        register()
        now += due
        server.nonce("n1")
        server.answer(200, "{\"status\":\"active\",\"revocationCodeIssued\":true}")

        client.status(withEvidence = true)

        take()
        assertFalse(take().json().has("android_key_attestation_x5c"))
        assertEquals(1, keys.made.size)
    }

    @Test
    fun aKeyAttestationWithChainsMovesTheTime() = runBlocking {
        register()
        now += due
        server.answer(200, "{\"keyAttestation\":\"ka.jwt\",\"attestationType\":\"android_keystore\",\"keyStorage\":[],\"attestedKeysCount\":1}")

        KeyAttestationService.requestBatchKeyAttestation(
            baseUrl = "x", walletUnitAttestationJWT = "w", walletUnitProofOfPossession = "p",
            nonce = "c", attestedKeys = listOf(softwareEcKey()),
            androidKeyAttestationX5cChains = listOf(listOf("a")), walletProvider = client
        )

        assertEquals(now, keys.chainAcceptedAt)
    }

    @Test
    fun aKeyAttestationWithoutChainsKeepsTheTime() = runBlocking {
        register()
        val registeredAt = now
        now += due
        server.answer(200, "{\"keyAttestation\":\"ka.jwt\",\"attestationType\":\"software\",\"keyStorage\":[],\"attestedKeysCount\":1}")

        KeyAttestationService.requestBatchKeyAttestation(
            baseUrl = "x", walletUnitAttestationJWT = "w", walletUnitProofOfPossession = "p",
            nonce = "c", attestedKeys = listOf(softwareEcKey()), walletProvider = client
        )

        assertEquals(registeredAt, keys.chainAcceptedAt)
    }

    @Test
    fun aResetForgetsTheTime() = runBlocking {
        register()
        client.reset()
        assertNull(keys.chainAcceptedAt)
    }
}
