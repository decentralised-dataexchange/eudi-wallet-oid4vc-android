package com.ewc.eudi_wallet_oidc_android.services

import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.ServerErrorCodes
import com.ewc.eudi_wallet_oidc_android.services.network.HttpErrorException
import com.ewc.eudi_wallet_oidc_android.services.utils.ErrorHandler
import org.junit.Assert
import org.junit.Test
import kotlin.collections.iterator

/**
 * What the app is promised about an error from the L3-iGrant api and wallet (api#2331):
 *
 *  - the OAuth endpoints keep {"error", "error_description"}: the code is the key;
 *  - everything else is an RFC 9457 problem (type, title, status, detail, requestId) with no code:
 *    the HTTP status is the key, and requestId is what a user quotes to support;
 *  - X-Request-Id is on every response, so a header id wins over the body's.
 *
 * Complements ErrorHandlerTest, which pins the description rules. Every case here is a success
 * path of the parser, so none touches android.util.Log. The parser uses org.json, so the unit-test
 * classpath needs `testImplementation("org.json:json:20231013")`: the copy inside android.jar is
 * a stub that throws.
 */
class ServerErrorContractTest {

    private fun problem(status: Int, detail: String, requestId: String? = "req-$status") =
        buildString {
            append("""{"type":"about:blank","title":"t","status":$status,"detail":"$detail"""")
            if (requestId != null) append(""","requestId":"$requestId"""")
            append("}")
        }

    // ---- RFC 9457 problems: status, detail, request id

    @Test
    fun `a problem gives its detail, status and request id and no code`() {
        val result = ErrorHandler.processError(problem(404, "Credential definition not found."), 404)
        Assert.assertEquals("Credential definition not found.", result?.errorDescription)
        Assert.assertEquals(404, result?.httpStatus)
        Assert.assertEquals("req-404", result?.requestId)
        Assert.assertNull(result?.errorCode)
    }

    @Test
    fun `every status the api and the wallet can answer reads the same way`() {
        // The statuses of the API team's census of 2026-11-03.
        val statuses = listOf(400, 401, 403, 404, 405, 409, 413, 415, 426, 429, 500, 502, 503, 504, 507)
        for (status in statuses) {
            val result = ErrorHandler.processError(problem(status, "A sentence."), status)
            Assert.assertEquals("A sentence.", result?.errorDescription)
            Assert.assertEquals(status, result?.httpStatus)
            Assert.assertEquals("req-$status", result?.requestId)
            Assert.assertNull(result?.errorCode)
        }
    }

    @Test
    fun `the 426 update answer is read from detail, not from its legacy members`() {
        val body = """{"type":"about:blank","title":"Upgrade Required","status":426,""" +
                """"detail":"Please update to the latest version to continue using this service.",""" +
                """"errorCode":426,"errorDescription":"Please update to the latest version to continue using this service."}"""
        val result = ErrorHandler.processError(body, 426)
        Assert.assertEquals(
            "Please update to the latest version to continue using this service.",
            result?.errorDescription
        )
        Assert.assertEquals(426, result?.httpStatus)
        Assert.assertNull(result?.errorCode) // the numeric legacy errorCode is not an OAuth code
    }

    @Test
    fun `the credential definition refusal with its extra members is read from detail`() {
        val body = """{"type":"about:blank","title":"Bad Request","status":400,""" +
                """"detail":"The credential definition is not valid.","requestId":"r",""" +
                """"errorType":"validation","errorField":"name","errorMessages":["is required"]}"""
        val result = ErrorHandler.processError(body, 400)
        Assert.assertEquals("The credential definition is not valid.", result?.errorDescription)
        Assert.assertNull(result?.errorCode)
    }

    // ---- the status, when the caller did not have one

    @Test
    fun `the status in a problem body is used when the caller passed none`() {
        Assert.assertEquals(
            503,
            ErrorHandler.processError(problem(503, "Try again later."))?.httpStatus
        )
    }

    @Test
    fun `the status the caller passed wins over the body`() {
        Assert.assertEquals(502, ErrorHandler.processError(problem(503, "x"), 502)?.httpStatus)
    }

    @Test
    fun `a status member of an oauth body is not taken for a problem status`() {
        // No title or type, so this is not an RFC 9457 problem.
        Assert.assertNull(ErrorHandler.processError("""{"error":"invalid_request","status":404}""")?.httpStatus)
        // A title, but the status is not a number.
        Assert.assertNull(
            ErrorHandler.processError("""{"title":"x","status":"failed","detail":"d"}""")?.httpStatus
        )
        // A number outside the HTTP range.
        Assert.assertNull(ErrorHandler.processError("""{"title":"x","status":7,"detail":"d"}""")?.httpStatus)
    }

    // ---- the request id

    @Test
    fun `the X-Request-Id header wins over the id in the body`() {
        val result = ErrorHandler.processError(problem(500, "x"), 500, "from-header")
        Assert.assertEquals("from-header", result?.requestId)
    }

    @Test
    fun `the header id is kept for an oauth body, which carries none`() {
        val result = ErrorHandler.processError("""{"error":"server_error"}""", 500, "hdr-1")
        Assert.assertEquals("hdr-1", result?.requestId)
        Assert.assertEquals("server_error", result?.errorCode)
    }

    @Test
    fun `an oauth body has no request id unless the header gave one`() {
        Assert.assertNull(
            ErrorHandler.processError(
                """{"error":"invalid_request"}""",
                400
            )?.requestId
        )
    }

    @Test
    fun `an error rebuilt from the raw body still finds the body request id`() {
        // Several failure paths rebuild an ErrorResponse and keep only the raw body.
        val rebuilt = ErrorResponse(errorDescription = "d", raw = problem(503, "x"))
        Assert.assertEquals("req-503", rebuilt.requestId)
    }

    @Test
    fun `a request id that was set explicitly wins over the raw body`() {
        val rebuilt = ErrorResponse(errorDescription = "d", raw = problem(503, "x"))
        rebuilt.requestId = "explicit"
        Assert.assertEquals("explicit", rebuilt.requestId)
    }

    @Test
    fun `a raw body that is not json has no request id`() {
        Assert.assertNull(ErrorResponse(raw = "<html>Bad gateway</html>").requestId)
        Assert.assertNull(ErrorResponse(raw = null).requestId)
    }

    // ---- the oauth code

    @Test
    fun `the code is trimmed and lower-cased so it compares with ServerErrorCodes as it is`() {
        val result = ErrorHandler.processError("""{"error":"  Invalid_Grant "}""")
        Assert.assertEquals(ServerErrorCodes.INVALID_GRANT, result?.errorCode)
    }

    @Test
    fun `a code nested under detail is normalised too`() {
        val result = ErrorHandler.processError(
            """{"detail":{"error":" INVALID_NONCE ","error_description":"nonce expired"}}"""
        )
        Assert.assertEquals(ServerErrorCodes.INVALID_NONCE, result?.errorCode)
        Assert.assertEquals("nonce expired", result?.errorDescription)
    }

    @Test
    fun `a blank code is no code`() {
        Assert.assertNull(ErrorHandler.processError("""{"error":"   "}""")?.errorCode)
        Assert.assertNull(ErrorHandler.processError("""{"error":""}""")?.errorCode)
    }

    // ---- failures that SafeApiCall turned into exceptions

    @Test
    fun `a failure carries the status and request id of its response`() {
        val failure = HttpErrorException(
            503,
            "id-503",
            problem(503, "The wallet service is not available right now. Try again later.", null)
        )
        val result = ErrorHandler.processFailure(failure)
        Assert.assertEquals(
            "The wallet service is not available right now. Try again later.",
            result?.errorDescription
        )
        Assert.assertEquals(503, result?.httpStatus)
        Assert.assertEquals("id-503", result?.requestId)
    }

    @Test
    fun `a failure keeps the oauth code of its body`() {
        val failure = HttpErrorException(
            403, "id-403",
            """{"error":"credential_request_denied","error_description":"Not allowed."}"""
        )
        val result = ErrorHandler.processFailure(failure)
        Assert.assertEquals(ServerErrorCodes.CREDENTIAL_REQUEST_DENIED, result?.errorCode)
        Assert.assertEquals("Not allowed.", result?.errorDescription)
        Assert.assertEquals(403, result?.httpStatus)
    }

    @Test
    fun `the message of a failure is still the body, so nothing reading it changes`() {
        val body = """{"error":"invalid_request"}"""
        Assert.assertEquals(body, HttpErrorException(400, null, body).message)
    }

    @Test
    fun `a transport failure has no status and no request id`() {
        val result = ErrorHandler.processFailure(Exception("No Internet or DNS issue"))
        Assert.assertNotNull(result)
        Assert.assertNull(result?.httpStatus)
        Assert.assertNull(result?.requestId)
        Assert.assertEquals("No Internet or DNS issue", result?.errorDescription)
    }

    // ---- the published code constants

    @Test
    fun `the code constants are spelled as the specifications spell them`() {
        val expected = mapOf(
            ServerErrorCodes.INVALID_REQUEST to "invalid_request",
            ServerErrorCodes.INVALID_CLIENT to "invalid_client",
            ServerErrorCodes.INVALID_GRANT to "invalid_grant",
            ServerErrorCodes.UNAUTHORIZED_CLIENT to "unauthorized_client",
            ServerErrorCodes.ACCESS_DENIED to "access_denied",
            ServerErrorCodes.INVALID_TOKEN to "invalid_token",
            ServerErrorCodes.SERVER_ERROR to "server_error",
            ServerErrorCodes.TEMPORARILY_UNAVAILABLE to "temporarily_unavailable",
            ServerErrorCodes.INVALID_CREDENTIAL_REQUEST to "invalid_credential_request",
            ServerErrorCodes.UNKNOWN_CREDENTIAL_CONFIGURATION to "unknown_credential_configuration",
            ServerErrorCodes.UNKNOWN_CREDENTIAL_IDENTIFIER to "unknown_credential_identifier",
            ServerErrorCodes.INVALID_PROOF to "invalid_proof",
            ServerErrorCodes.INVALID_NONCE to "invalid_nonce",
            ServerErrorCodes.CREDENTIAL_REQUEST_DENIED to "credential_request_denied",
            ServerErrorCodes.INVALID_TRANSACTION_ID to "invalid_transaction_id",
            ServerErrorCodes.ISSUANCE_PENDING to "issuance_pending",
            ServerErrorCodes.VP_FORMATS_NOT_SUPPORTED to "vp_formats_not_supported",
            ServerErrorCodes.INVALID_TRANSACTION_DATA to "invalid_transaction_data",
            ServerErrorCodes.WALLET_UNAVAILABLE to "wallet_unavailable",
        )
        for ((constant, spelling) in expected) Assert.assertEquals(spelling, constant)
        // Every constant is a distinct, already-normalised value.
        Assert.assertEquals(expected.size, expected.keys.toSet().size)
    }
}