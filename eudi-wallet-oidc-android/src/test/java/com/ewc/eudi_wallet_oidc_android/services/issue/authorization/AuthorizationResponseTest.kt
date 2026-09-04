package com.ewc.eudi_wallet_oidc_android.services.issue.authorization

import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The response object's own contract.
 *
 * Two things are pinned here. First, that each factory sets exactly the fields its outcome
 * documents -- the class KDoc carries that table, and a reader has to be able to trust it. Second,
 * that `location` still holds what the deprecated `processAuthorisationRequest` returns, because
 * callers that have not migrated parse `code` and `error` back out of that string.
 */
class AuthorizationResponseTest {

    /** Mirrors the flattening in `IssueService.processAuthorisationRequest`. */
    private fun asDeprecatedString(response: AuthorizationResponse): String? =
        when (response.outcome) {
            AuthorizationOutcome.AUTHORIZATION_CODE -> response.location
            AuthorizationOutcome.OPEN_IN_BROWSER -> response.url
            AuthorizationOutcome.PRESENTATION_REQUIRED -> response.url
            AuthorizationOutcome.ID_TOKEN_REQUIRED -> response.url
            AuthorizationOutcome.FAILED -> response.location
        }

    @Test
    fun `an authorization code carries the code, the state and the redirect it arrived on`() {
        val response = AuthorizationResponse.authorizationCode(
            code = "abc123",
            state = "xyz",
            location = "openid://callback?code=abc123&state=xyz",
        )

        assertEquals(AuthorizationOutcome.AUTHORIZATION_CODE, response.outcome)
        assertEquals("abc123", response.code)
        assertEquals("xyz", response.state)
        assertNull(response.url)
        assertNull(response.error)
        // what the deprecated entry point returned, and still does
        assertEquals("openid://callback?code=abc123&state=xyz", asDeprecatedString(response))
    }

    @Test
    fun `a browser hand-off carries the url and the lifetime`() {
        val response = AuthorizationResponse.openInBrowser("https://as.example/authorize?x=1", 90)

        assertEquals(AuthorizationOutcome.OPEN_IN_BROWSER, response.outcome)
        assertEquals(90, response.expiresIn)
        assertNull(response.code)
        assertEquals("https://as.example/authorize?x=1", asDeprecatedString(response))
    }

    @Test
    fun `a presentation request carries the auth session`() {
        val response = AuthorizationResponse.presentationRequired(
            url = "https://as.example/authorize?auth_session=s1",
            authSession = "s1",
            expiresIn = 120,
        )

        assertEquals(AuthorizationOutcome.PRESENTATION_REQUIRED, response.outcome)
        assertEquals("s1", response.authSession)
        assertEquals(120, response.expiresIn)
        assertNull(response.code)
    }

    @Test
    fun `an id token request carries only the url to answer`() {
        val response = AuthorizationResponse.idTokenRequired("https://as.example/cb?response_type=id_token")

        assertEquals(AuthorizationOutcome.ID_TOKEN_REQUIRED, response.outcome)
        assertNull(response.authSession)
        assertNull(response.error)
        assertEquals("https://as.example/cb?response_type=id_token", asDeprecatedString(response))
    }

    /**
     * A failure with no redirect returns null through the deprecated entry point, exactly as it
     * always did -- the compatibility shim must not start returning strings where it returned null.
     */
    @Test
    fun `a failure without a redirect still flattens to null`() {
        val response = AuthorizationResponse.failed("The authorization request was refused", httpStatus = 400)

        assertEquals(AuthorizationOutcome.FAILED, response.outcome)
        assertEquals(400, response.error?.httpStatus)
        assertNull(asDeprecatedString(response))
    }

    @Test
    fun `a failure read off a redirect keeps that redirect for callers that parse it`() {
        val location = "openid://callback?error=access_denied&error_description=nope"
        val response = AuthorizationResponse.failed(
            reason = "nope",
            errorCode = "access_denied",
            location = location,
        )

        assertEquals("access_denied", response.error?.errorCode)
        assertEquals(location, asDeprecatedString(response))
    }

    /** One error shape across the SDK: the same type the token and credential steps return. */
    @Test
    fun `the error is the SDK-wide ErrorResponse`() {
        val error = ErrorResponse(
            error = -1,
            errorDescription = "Issuer state is not found",
            errorCode = "invalid_grant",
            httpStatus = 400,
        )

        val response = AuthorizationResponse.failed(error)

        assertEquals(error, response.error)
        assertEquals("invalid_grant", response.error?.errorCode)
    }
}
