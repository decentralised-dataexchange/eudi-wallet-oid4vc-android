package com.ewc.eudi_wallet_oidc_android

import com.ewc.eudi_wallet_oidc_android.services.network.HttpErrorException
import com.ewc.eudi_wallet_oidc_android.services.utils.ErrorHandler
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * What the app is promised about an error: the server's `error` code (normalised), the HTTP
 * status, the request id, and a description that has not changed.
 *
 * The parser uses org.json, so the unit-test classpath needs `testImplementation("org.json:json:20231013")`
 * (the one inside android.jar is a stub that throws).
 */
class ErrorHandlerTest {

    private val problem404 = """{"type":"about:blank","title":"Not Found","status":404,"detail":"Credential definition not found.","requestId":"54f37f12-7cc3-44ed-98dd-aaa06470919e"}"""

    // ---- OAuth bodies (issuer, authorization server, direct_post, wallet provider)

    @Test
    fun oauthBodyKeepsCodeAndDescription() {
        val e = ErrorHandler.processError(
            """{"error":"credential_request_denied","error_description":"Credential request denied."}""", 400
        )
        assertEquals("credential_request_denied", e?.errorCode)
        assertEquals("Credential request denied.", e?.errorDescription)
        assertEquals(400, e?.httpStatus)
    }

    @Test
    fun codeAloneBecomesTheDescriptionToo() {
        val e = ErrorHandler.processError("""{"error":"invalid_token"}""")
        assertEquals("invalid_token", e?.errorCode)
        assertEquals("invalid_token", e?.errorDescription)
    }

    @Test
    fun codeIsTrimmedAndLowerCased() {
        val e = ErrorHandler.processError("""{"error":"  Invalid_Grant "}""")
        assertEquals("invalid_grant", e?.errorCode)
    }

    @Test
    fun whitespaceOnlyCodeIsNoCode() {
        assertNull(ErrorHandler.processError("""{"error":"   "}""")?.errorCode)
        assertNull(ErrorHandler.processError("""{"error":""}""")?.errorCode)
    }

    @Test
    fun codeNestedUnderDetail() {
        val e = ErrorHandler.processError("""{"detail":{"error":"invalid_nonce","error_description":"nonce expired"}}""")
        assertEquals("invalid_nonce", e?.errorCode)
        assertEquals("nonce expired", e?.errorDescription)
    }

    @Test
    fun errorThatIsNotAStringIsNotACode() {
        assertNull(ErrorHandler.processError("""{"error":{"nested":1}}""")?.errorCode)
    }

    @Test
    fun oauthBodyHasNoRequestId() {
        assertNull(ErrorHandler.processError("""{"error":"invalid_request"}""", 400)?.requestId)
    }

    // ---- RFC 9457 problems (api, wallet config and service routes)

    @Test
    fun problemGivesItsDetailTheStatusAndTheBodyRequestId() {
        val e = ErrorHandler.processError(problem404, 404)
        assertEquals("Credential definition not found.", e?.errorDescription)
        assertEquals(404, e?.httpStatus)
        assertEquals("54f37f12-7cc3-44ed-98dd-aaa06470919e", e?.requestId)
        assertNull(e?.errorCode)
    }

    @Test
    fun headerRequestIdWinsOverTheBody() {
        val e = ErrorHandler.processError(problem404, 404, "from-header")
        assertEquals("from-header", e?.requestId)
    }

    @Test
    fun headerRequestIdIsKeptWhenTheBodyHasNone() {
        val e = ErrorHandler.processError("""{"error":"server_error"}""", 500, "hdr-1")
        assertEquals("hdr-1", e?.requestId)
        assertEquals("server_error", e?.errorCode)
    }

    @Test
    fun upgradeRequiredBodyWithTheLegacyMembersIsReadFromDetail() {
        val e = ErrorHandler.processError(
            """{"type":"about:blank","title":"Upgrade Required","status":426,"detail":"Please update to the latest version to continue using this service.","errorCode":426,"errorDescription":"Please update to the latest version to continue using this service."}""",
            426
        )
        assertEquals("Please update to the latest version to continue using this service.", e?.errorDescription)
        assertEquals(426, e?.httpStatus)
        assertNull(e?.errorCode) // the legacy numeric errorCode is not an OAuth code
    }

    @Test
    fun problemStatusInTheBodyIsUsedWhenTheCallerPassedNone() {
        val e = ErrorHandler.processError(problem404)
        assertEquals(404, e?.httpStatus)
    }

    @Test
    fun callerStatusWinsOverTheBodyStatus() {
        assertEquals(503, ErrorHandler.processError(problem404, 503)?.httpStatus)
    }

    @Test
    fun aStatusMemberOfAnOAuthBodyIsNotAProblemStatus() {
        // no title or type: not an RFC 9457 problem
        assertNull(ErrorHandler.processError("""{"error":"invalid_request","status":404}""")?.httpStatus)
        // a status that is not a number in the HTTP range
        assertNull(ErrorHandler.processError("""{"type":"about:blank","title":"x","status":"failed","detail":"d"}""")?.httpStatus)
    }

    @Test
    fun everyStatusTheApiAndWalletCanAnswerReadsAsAProblem() {
        // the statuses of the API team's census (2026-11-03), all the same body shape
        for (status in listOf(400, 401, 403, 404, 405, 409, 413, 415, 426, 429, 500, 502, 503, 504, 507)) {
            val body = """{"type":"about:blank","title":"t","status":$status,"detail":"A sentence.","requestId":"r-$status"}"""
            val e = ErrorHandler.processError(body, status)
            assertEquals("A sentence.", e?.errorDescription)
            assertEquals(status, e?.httpStatus)
            assertEquals("r-$status", e?.requestId)
            assertNull(e?.errorCode)
        }
    }

    @Test
    fun credentialDefinitionRefusalWithItsExtraMembersReadsFromDetail() {
        val e = ErrorHandler.processError(
            """{"type":"about:blank","title":"Bad Request","status":400,"detail":"The credential definition is not valid.","requestId":"r","errorType":"validation","errorField":"name","errorMessages":["is required"]}""",
            400
        )
        assertEquals("The credential definition is not valid.", e?.errorDescription)
        assertNull(e?.errorCode)
    }

    // ---- bodies that are not JSON

    @Test
    fun htmlAndPlainTextHaveNoCode() {
        assertNull(ErrorHandler.processError("<html>Bad gateway</html>", 502)?.errorCode)
        assertNull(ErrorHandler.processError("No Internet or DNS issue")?.errorCode)
    }

    // ---- failures that SafeApiCall converted

    @Test
    fun failureCarriesTheStatusAndRequestIdOfTheResponse() {
        val failure = HttpErrorException(
            503, "id-503",
            """{"type":"about:blank","title":"Service Unavailable","status":503,"detail":"The wallet service is not available right now. Try again later."}"""
        )
        val e = ErrorHandler.processFailure(failure)
        assertEquals("The wallet service is not available right now. Try again later.", e?.errorDescription)
        assertEquals(503, e?.httpStatus)
        assertEquals("id-503", e?.requestId)
    }

    @Test
    fun aTransportFailureHasNoStatus() {
        val e = ErrorHandler.processFailure(Exception("No Internet or DNS issue"))
        assertNotNull(e)
        assertNull(e?.httpStatus)
        assertNull(e?.requestId)
    }
}
