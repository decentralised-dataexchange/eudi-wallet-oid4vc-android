package com.ewc.eudi_wallet_oidc_android

import com.ewc.eudi_wallet_oidc_android.services.discovery.DiscoveryService
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The public contract of [DiscoveryService]. The behaviour of each piece behind it is covered by
 * the suites in `services/discovery/metadata`.
 *
 * Malformed and null inputs are rejected before any HTTP call, so these stay offline.
 *
 * These assertions changed with the OpenID4VCI 1.0 rework: `getIssuerConfig` used to return a bare
 * `null` for unusable input, which a caller could not distinguish from a network failure -- and
 * the wallet's error branch, an `if / else if` with no `else`, fired for neither, leaving its
 * spinner running. Every outcome now carries an `errorResponse`.
 */
class DiscoveryServiceTest {

    private val discoveryService = DiscoveryService()

    @Test
    fun `null issuer uri reports an error rather than returning null`() {
        val result = runBlocking { discoveryService.getIssuerConfig(null) }
        assertNull(result.issuerConfig)
        assertNotNull(result.errorResponse?.errorDescription)
    }

    @Test
    fun `malformed issuer uri reports a validation error rather than a config`() {
        val result = runBlocking { discoveryService.getIssuerConfig("://abc") }
        assertNull(result.issuerConfig)
        assertNotNull(result.errorResponse?.errorDescription)
    }

    @Test
    fun `null auth server uri reports an error rather than a config`() {
        val result = runBlocking { discoveryService.getAuthConfig(null) }
        assertNull(result.authConfig)
        assertNotNull(result.errorResponse?.errorDescription)
    }

    @Test
    fun `malformed auth server uri reports a validation error rather than a config`() {
        val result = runBlocking { discoveryService.getAuthConfig("://abc") }
        assertNull(result.authConfig)
        assertNotNull(result.errorResponse?.errorDescription)
    }
}
