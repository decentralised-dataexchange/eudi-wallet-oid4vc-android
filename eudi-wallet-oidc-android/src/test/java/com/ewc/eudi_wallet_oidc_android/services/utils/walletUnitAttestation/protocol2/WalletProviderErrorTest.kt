package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.protocol2

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The error ids of CONTRACT.md section 4 and what the app does for each. */
class WalletProviderErrorTest {

    @Test
    fun `each error id of the contract has its action`() {
        val expected = mapOf(
            "individual_wallet_unit.app_version_too_old" to WalletProviderErrorAction.UPDATE_APP,
            "individual_wallet_unit.app_unknown" to WalletProviderErrorAction.UPDATE_APP,
            "individual_wallet_unit.revoked" to WalletProviderErrorAction.REVOKED,
            "individual_wallet_unit.suspended" to WalletProviderErrorAction.SUSPENDED,
            "individual_wallet_unit.device_refused" to WalletProviderErrorAction.DEVICE_REFUSED,
            "individual_wallet_unit.request_signature_invalid" to WalletProviderErrorAction.RETRY_WITH_NEW_NONCE,
            "individual_wallet_unit.protocol_1_refused" to WalletProviderErrorAction.NOTHING,
            "individual_wallet_unit.nonce_refused" to WalletProviderErrorAction.GENERAL,
            "kit.nonce_rate_limited" to WalletProviderErrorAction.GENERAL
        )
        for ((id, action) in expected) assertEquals(id, action, WalletProviderError.actionFor(id))
        assertEquals(WalletProviderErrorAction.GENERAL, WalletProviderError.actionFor(null))
    }

    @Test
    fun `the error body is read with its reason`() {
        val error = WalletProviderError.parse(
            403,
            "{\"error\":\"access_denied\",\"error_description\":\"The device is not accepted.\"," +
                "\"error_id\":\"individual_wallet_unit.device_refused\",\"reason\":\"integrity_failed\"}"
        )
        assertEquals(403, error.httpCode)
        assertEquals("access_denied", error.error)
        assertEquals("The device is not accepted.", error.errorDescription)
        assertEquals("integrity_failed", error.reason)
        assertEquals(WalletProviderErrorAction.DEVICE_REFUSED, error.action)
    }

    @Test
    fun `a body that is not a JSON object is a general error`() {
        for (body in listOf(null, "", "<html>bad gateway</html>", "[1,2]", "\"text\"")) {
            val error = WalletProviderError.parse(502, body)
            assertNull(error.errorId)
            assertEquals(WalletProviderErrorAction.GENERAL, error.action)
        }
        assertTrue(WalletProviderError(null).isTransport)
    }
}
