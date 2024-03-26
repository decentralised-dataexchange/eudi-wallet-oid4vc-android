package com.ewc.eudi_wallet_oidc_android

import com.ewc.eudi_wallet_oidc_android.services.did.DIDService
import com.ewc.eudi_wallet_oidc_android.services.discovery.DiscoveryService
import kotlinx.coroutines.runBlocking
import org.junit.Assert
import org.junit.Test

class DIDServiceTest {

    private val didService = DIDService()

    @Test
    fun createJWKSuccess() {
        val kty = "EC"
        val subJWK = didService.createJWK()
        Assert.assertNotNull(subJWK)
        Assert.assertEquals(kty,subJWK.keyType.value)
    }

    @Test
    fun createJWKSuccessWithSeed() {
        val kty = "EC"
        val seed = "abc"
        val subJWK = didService.createJWK(seed)
        Assert.assertNotNull(subJWK)
        Assert.assertEquals(kty,subJWK.keyType.value)
    }

}