package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation

import com.ewc.eudi_wallet_oidc_android.BatchWalletAttestationResult
import com.ewc.eudi_wallet_oidc_android.BatchWalletUnit
import com.ewc.eudi_wallet_oidc_android.WalletAttestationResult
import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.models.ErrorCodes
import com.ewc.eudi_wallet_oidc_android.models.WalletProviderOutcome
import com.ewc.eudi_wallet_oidc_android.models.WalletUnitRevocationCodeOutcome
import com.ewc.eudi_wallet_oidc_android.models.WalletUnitStatus
import com.ewc.eudi_wallet_oidc_android.models.WalletUnitStatusOutcome
import com.ewc.eudi_wallet_oidc_android.services.utils.ErrorHandler
import com.nimbusds.jose.jwk.ECKey
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class Protocol1WalletProviderClientTest {

    private class FakeService : Protocol1WalletUnitAttestation {
        var single: WalletAttestationResult? = null
        var batch: BatchWalletAttestationResult? = null
        var batchClientId: String? = null
        override suspend fun single(baseUrl: String, cnfKey: ECKey, profile: String?) = single
        override suspend fun batch(baseUrl: String, cnfKeys: List<ECKey>, clientId: String, profile: String?): BatchWalletAttestationResult? {
            batchClientId = clientId
            return batch
        }
    }

    private val service = FakeService()
    private val client = Protocol1WalletProviderClient("https://wp/service", service)

    private fun batch(httpCode: Int?, wia: String?) = BatchWalletAttestationResult(
        clientId = "c", requestHash = null, httpCode = httpCode, errorBody = "body", credentialOffer = null,
        credentialIssuer = null, units = listOf(BatchWalletUnit(0, "did", softwareEcKey(), "a", wia))
    )

    @Test
    fun aWiaIsASuccess() = runBlocking {
        service.single = WalletAttestationResult(walletUnitAttestation = "wia")
        val outcome = client.requestWalletUnitAttestation(softwareEcKey(), "c", "ts3")
        assertEquals("wia", (outcome as WalletProviderOutcome.Success).value.walletUnitAttestation)
    }

    @Test
    fun noAnswerOrAnEmptyAnswerFails() = runBlocking {
        service.single = null
        assertEquals(ErrorCodes.WALLET_PROVIDER_REQUEST_FAILED,
            (client.requestWalletUnitAttestation(softwareEcKey(), "c", null) as WalletProviderOutcome.Failed).error.error)
        service.single = WalletAttestationResult()
        assertTrue(client.requestWalletUnitAttestation(softwareEcKey(), "c", null) is WalletProviderOutcome.Failed)
    }

    @Test
    fun aBatchPassesTheClientIdAndSucceedsWithAttestations() = runBlocking {
        service.batch = batch(200, "w0")
        assertTrue(client.requestWalletUnitAttestations(listOf(softwareEcKey()), "unit", null) is WalletProviderOutcome.Success)
        assertEquals("unit", service.batchClientId)
    }

    @Test
    fun aRefusedBatchFailsWithTheHttpStatusAndNoErrorId() = runBlocking {
        service.batch = batch(404, null)
        val error = (client.requestWalletUnitAttestations(listOf(softwareEcKey()), "unit", null) as WalletProviderOutcome.Failed).error
        assertEquals(404, error.httpStatus)
        assertNull(error.errorId)
        service.batch = null
        assertTrue(client.requestWalletUnitAttestations(listOf(softwareEcKey()), "unit", null) is WalletProviderOutcome.Failed)
        assertTrue(client.requestWalletUnitAttestations(emptyList(), "unit", null) is WalletProviderOutcome.Failed)
    }

    @Test
    fun protocol1HasNoStatusNoCodeAndNoLostKey() = runBlocking {
        assertEquals(WalletUnitStatusOutcome.NotSupported, client.status(true))
        assertEquals(WalletUnitRevocationCodeOutcome.NotSupported, client.revocationCode())
        assertFalse(client.isKeyLost)
        client.reset()
    }

    // Shared pieces of protocol 2 that need no server.

    @Test
    fun theErrorHandlerReadsTheErrorIdAndReason() {
        val error = ErrorHandler.processError(refusal("revoked", "user_request"), 403)!!
        assertEquals("individual_wallet_unit.revoked", error.errorId)
        assertEquals("user_request", error.reason)
        assertEquals("invalid_client", error.errorCode)
        assertEquals("refused", error.errorDescription)
        assertNull(ErrorHandler.processError("{\"error\":\"invalid_grant\"}", 400)!!.errorId)
    }

    @Test
    fun theRevocationCodeIsNeverLogged() {
        val line = "{\"walletUnitAttestation\":\"w\",\"revocationCode\" : \"7KQ2 M9XA H4TD 0RWE 5BNC\"}"
        val hidden = Logger.hidingSecrets(line)
        assertFalse(hidden.contains("7KQ2"))
        assertTrue(hidden.contains("\"revocationCode\":\"<hidden>\""))
        assertTrue(hidden.contains("\"walletUnitAttestation\":\"w\""))
    }

    @Test
    fun aStatusAnswerIsRead() {
        val status = WalletUnitStatus.parse("{\"status\":\"revoked\",\"reason\":\"user_request\",\"revokedAt\":\"2026-11-13T10:00:00Z\",\"deviceCheckDue\":false,\"revocationCodeIssued\":true}")!!
        assertTrue(status.isRevoked)
        assertEquals("2026-11-13T10:00:00Z", status.revokedAt)
        val minimal = WalletUnitStatus.parse("{\"status\":\"active\",\"reason\":null}")!!
        assertTrue(minimal.isActive)
        assertNull(minimal.reason)
        assertFalse(minimal.deviceCheckDue)
        assertTrue(minimal.revocationCodeIssued)
        assertNull(WalletUnitStatus.parse("{}"))
        assertNull(WalletUnitStatus.parse("not json"))
    }
}
