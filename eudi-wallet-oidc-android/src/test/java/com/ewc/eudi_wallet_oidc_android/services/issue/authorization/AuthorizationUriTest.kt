package com.ewc.eudi_wallet_oidc_android.services.issue.authorization

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Built on `java.net` rather than `android.net.Uri` so the package is testable off a device --
 * `android.net.Uri` returns null from every method in a JVM unit test.
 */
class AuthorizationUriTest {

    @Test
    fun `reads a query parameter`() {
        val url = "https://as.example.com/cb?code=abc&state=xyz"
        assertEquals("abc", AuthorizationUri.queryParameter(url, "code"))
        assertEquals("xyz", AuthorizationUri.queryParameter(url, "state"))
    }

    @Test
    fun `decodes percent escapes and plus`() {
        val url = "https://x/cb?error_description=Something%20went+wrong"
        assertEquals("Something went wrong", AuthorizationUri.queryParameter(url, "error_description"))
    }

    @Test
    fun `returns null for a missing parameter, no query, or null input`() {
        assertNull(AuthorizationUri.queryParameter("https://x/cb?code=1", "state"))
        assertNull(AuthorizationUri.queryParameter("https://x/cb", "code"))
        assertNull(AuthorizationUri.queryParameter(null, "code"))
    }

    @Test
    fun `ignores the fragment`() {
        assertNull(AuthorizationUri.queryParameter("https://x/cb#?code=1", "code"))
    }

    @Test
    fun `appends parameters and skips blanks`() {
        val url = AuthorizationUri.appendQueryParameters(
            "https://as.example.com/authorize",
            mapOf("client_id" to "abc", "request_uri" to "", "state" to null),
        )
        assertEquals("https://as.example.com/authorize?client_id=abc", url)
    }

    @Test
    fun `keeps an existing query`() {
        val url = AuthorizationUri.appendQueryParameters("https://x/a?one=1", mapOf("two" to "2"))
        assertTrue(url.contains("?one=1&two=2"))
    }
}
