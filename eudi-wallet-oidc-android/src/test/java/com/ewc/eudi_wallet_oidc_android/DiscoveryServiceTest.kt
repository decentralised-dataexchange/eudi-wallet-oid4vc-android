package com.ewc.eudi_wallet_oidc_android

import com.ewc.eudi_wallet_oidc_android.services.UriValidationFailed
import com.ewc.eudi_wallet_oidc_android.services.UrlUtils
import com.ewc.eudi_wallet_oidc_android.services.discovery.DiscoveryService
import com.ewc.eudi_wallet_oidc_android.services.issue.IssueService
import kotlinx.coroutines.runBlocking
import org.junit.Assert
import org.junit.Test

class DiscoveryServiceTest {

    private val discoveryService = DiscoveryService()

    @Test
    fun issuerConfigUrlIsNull() {
        val result = runBlocking { discoveryService.getIssuerConfig(null)}
        Assert.assertNull(result)
    }

    @Test
    fun issuerConfigUrlIsNotValid() {
        val result = runBlocking { discoveryService.getIssuerConfig("://abc")}
        Assert.assertNull(result)
    }

    @Test
    fun authConfigUrlIsNull() {
        val result = runBlocking { discoveryService.getAuthConfig(null)}
        Assert.assertNull(result)
    }

    @Test
    fun authConfigUrlIsNotValid() {
        val result = runBlocking { discoveryService.getAuthConfig("://abc")}
        Assert.assertNull(result)
    }
}