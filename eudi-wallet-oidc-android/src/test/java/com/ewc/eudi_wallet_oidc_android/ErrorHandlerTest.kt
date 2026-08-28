package com.ewc.eudi_wallet_oidc_android

import com.ewc.eudi_wallet_oidc_android.services.utils.ErrorHandler
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Replaces the former IssueServiceTest, which called IssueService.processError() -- that method
 * moved to ErrorHandler, so the old file no longer compiled and the whole test source set was dead.
 *
 * These assert ErrorHandler's *current* behaviour. Two of them differ from what the old test
 * expected: a null or unrecognised error now yields ErrorResponse(error = -1) rather than null.
 * Whether "no error" should be representable again is a separate question, tracked outside this PR.
 */
class ErrorHandlerTest {

    @Test
    fun `null error yields error minus one with null description`() {
        val result = ErrorHandler.processError(null)
        assertEquals(-1, result?.error)
        assertNull(result?.errorDescription)
    }

    @Test
    fun `plain non-json string is passed through as the description`() {
        val result = ErrorHandler.processError("Invalid Proof JWT")
        assertEquals(-1, result?.error)
        assertEquals("Invalid Proof JWT", result?.errorDescription)
    }

    @Test
    fun `issuer not matching client id is mapped to a dedicated error code`() {
        val result =
            ErrorHandler.processError("Invalid Proof JWT: iss doesn't match the expected client_id")
        assertEquals(1, result?.error)
        assertEquals("DID is invalid", result?.errorDescription)
    }

    @Test
    fun `error description is preferred over error`() {
        val result = ErrorHandler.processError(
            """{"error":"Token request failed","error_description":"Invalid Client ID"}"""
        )
        assertEquals(-1, result?.error)
        assertEquals("Invalid Client ID", result?.errorDescription)
    }

    @Test
    fun `error alone is used when no description is present`() {
        val result = ErrorHandler.processError("""{"error":"Invalid Client ID"}""")
        assertEquals(-1, result?.error)
        assertEquals("Invalid Client ID", result?.errorDescription)
    }

    @Test
    fun `errors array uses the first message`() {
        val result = ErrorHandler.processError(
            """{"errors":[{"message":"Validation is failed"},{"message":"ignored"}]}"""
        )
        assertEquals(-1, result?.error)
        assertEquals("Validation is failed", result?.errorDescription)
    }

    @Test
    fun `errors object is flattened to key and first value`() {
        val result = ErrorHandler.processError("""{"errors":{"vct":["is required"]}}""")
        assertEquals(-1, result?.error)
        assertEquals("vct: is required", result?.errorDescription)
    }

    @Test
    fun `detail string is used as the description`() {
        val result = ErrorHandler.processError("""{"detail":"VC token expired"}""")
        assertEquals(-1, result?.error)
        assertEquals("VC token expired", result?.errorDescription)
    }

    @Test
    fun `nested detail prefers its error description`() {
        val result = ErrorHandler.processError(
            """{"detail":{"error":"invalid_grant","error_description":"PIN is wrong"}}"""
        )
        assertEquals(-1, result?.error)
        assertEquals("PIN is wrong", result?.errorDescription)
    }

    @Test
    fun `html body is replaced with a generic message`() {
        val result = ErrorHandler.processError("<html><body>502 Bad Gateway</body></html>")
        assertEquals(-1, result?.error)
        assertEquals("Unexpected error, please try again.", result?.errorDescription)
    }

    @Test
    fun `message field is used when nothing more specific is present`() {
        val result = ErrorHandler.processError("""{"message":"Something went wrong"}""")
        assertEquals(-1, result?.error)
        assertEquals("Something went wrong", result?.errorDescription)
    }

    @Test
    fun `unrecognised json object is flattened to its first entry`() {
        val result = ErrorHandler.processError("""{"reason":"unsupported_format"}""")
        assertEquals(-1, result?.error)
        assertEquals("reason: unsupported_format", result?.errorDescription)
    }
}
