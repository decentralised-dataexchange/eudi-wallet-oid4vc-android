package com.ewc.eudi_wallet_oidc_android

import com.ewc.eudi_wallet_oidc_android.services.UriValidationFailed
import com.ewc.eudi_wallet_oidc_android.services.UrlUtils
import org.junit.Assert
import org.junit.Test

// @RunWith(AndroidJUnit4::class)
class UrlUtilsTest {

    @Test
    fun urlisblank() {
        Assert.assertThrows(UriValidationFailed::class.java) {
            UrlUtils.validateUri("")
        }
    }

    @Test
    fun urlisinvalid() {
        Assert.assertThrows(UriValidationFailed::class.java) {
            UrlUtils.validateUri("://abc")
        }
    }
}