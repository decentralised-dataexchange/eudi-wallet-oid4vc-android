package com.ewc.eudi_wallet_oidc_android.services.tokenRefresh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class TokenRefreshServiceTest {

    @Test
    fun `a refused refresh token carries the OAuth error code`() {
        val body = """{"error":"invalid_grant","error_description":"Refresh token revoked"}"""
        val error = TokenRefreshService.refusal(400, body, "Bad Request")
        assertEquals("invalid_grant", error.errorCode)
        assertEquals(400, error.error)
        assertEquals(400, error.httpStatus)
        assertEquals(body, error.errorDescription)
        assertEquals(body, error.raw)
    }

    @Test
    fun `a body that is not an OAuth error keeps the old shape`() {
        val error = TokenRefreshService.refusal(502, "Bad Gateway", "Bad Gateway")
        assertNull(error.errorCode)
        assertEquals(502, error.error)
        assertEquals("Bad Gateway", error.errorDescription)
    }

    @Test
    fun `no body falls back to the HTTP message`() {
        val error = TokenRefreshService.refusal(401, null, "Unauthorized")
        assertNull(error.errorCode)
        assertEquals("Unauthorized", error.errorDescription)
    }
}
