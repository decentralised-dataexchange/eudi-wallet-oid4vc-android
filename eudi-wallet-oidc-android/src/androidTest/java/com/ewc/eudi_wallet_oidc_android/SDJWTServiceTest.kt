package com.ewc.eudi_wallet_oidc_android

import com.ewc.eudi_wallet_oidc_android.services.sdjwt.SDJWTService
import junit.framework.TestCase.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

class SDJWTServiceTest {

    private val sdjwtService = SDJWTService()

    @Test
    fun calculateSHA256Hash_ValidInput_ReturnsHash() {
        val inputString = "WyJtN2ZmSGJrbWJMemtSdWw0bkgxekN3IiwibGFzdE5hbWUiLCJEb2UiXQ"
        val expectedHash = "MZm30o204SUPQM36aJeF9ZsDhCTRu9t2uihXD93Y_cc"

        val actualHash = sdjwtService.calculateSHA256Hash(inputString)

        assertEquals(expectedHash, actualHash)
    }

    @Test
    fun calculateSHA256Hash_NullInput_ReturnsNull() {
        val actualHash = sdjwtService.calculateSHA256Hash(null)
        assertEquals(null, actualHash)
    }

}