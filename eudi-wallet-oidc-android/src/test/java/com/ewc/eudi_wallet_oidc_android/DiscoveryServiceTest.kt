package com.ewc.eudi_wallet_oidc_android

import com.ewc.eudi_wallet_oidc_android.services.discovery.DiscoveryService
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Malformed and null inputs are rejected by UrlUtils.validateUri before any HTTP call, so these
 * stay offline. The previous version asserted assertNull(getAuthConfig(...)), which can never hold:
 * getAuthConfig's implementation returns a non-null WrappedAuthConfigResponse carrying the error.
 */
class DiscoveryServiceTest {

    private val discoveryService = DiscoveryService()

    @Test
    fun `null issuer uri returns null before any request`() {
        val result = runBlocking { discoveryService.getIssuerConfig(null) }
        assertNull(result)
    }

    @Test
    fun `malformed issuer uri reports a validation error rather than a config`() {
        val result = runBlocking { discoveryService.getIssuerConfig("://abc") }
        assertNotNull(result)
        assertNull(result?.issuerConfig)
        assertNotNull(result?.errorResponse)
    }

    @Test
    fun `null auth server uri reports an error rather than a config`() {
        val result = runBlocking { discoveryService.getAuthConfig(null) }
        assertNull(result.authConfig)
        assertNotNull(result.errorResponse)
    }

    @Test
    fun `malformed auth server uri reports a validation error rather than a config`() {
        val result = runBlocking { discoveryService.getAuthConfig("://abc") }
        assertNull(result.authConfig)
        assertNotNull(result.errorResponse)
    }
}
