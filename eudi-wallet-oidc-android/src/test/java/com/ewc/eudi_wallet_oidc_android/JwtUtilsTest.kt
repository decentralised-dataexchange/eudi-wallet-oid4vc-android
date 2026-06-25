package com.ewc.eudi_wallet_oidc_android

import com.ewc.eudi_wallet_oidc_android.services.utils.JwtUtils
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class JwtUtilsTest {

    // Helper utility to produce clean base64url strings for structural testing
    private fun base64UrlEncode(input: String): String {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(input.toByteArray())
    }

    @Test
    fun `should return true for a valid structurally sound signed JWT`() {
        val headerJson = """{"alg":"RS256","typ":"JWT"}"""
        val payloadJson = """{"sub":"1234567890","iss":"eudi_wallet","exp":9999999999}"""
        val dummySignature = "q83_v_A8dxEOW0w"

        val validJwt = "${base64UrlEncode(headerJson)}.${base64UrlEncode(payloadJson)}.$dummySignature"

        val result = JwtUtils.isValidJwtStructure(validJwt)
        assertTrue(result)
    }

    @Test
    fun `should return true for a valid plain token with alg none`() {
        val headerJson = """{"alg":"none"}"""
        val payloadJson = """{"status_list":{"idx":0,"status":0}}"""

        // Plain tokens (alg:none) still end with a dot separating an empty signature slot
        val validPlainJwt = "${base64UrlEncode(headerJson)}.${base64UrlEncode(payloadJson)}."

        val result = JwtUtils.isValidJwtStructure(validPlainJwt)
        assertTrue(result)
    }

    @Test
    fun `should return false when input string is null or blank`() {
        assertFalse(JwtUtils.isValidJwtStructure(null))
        assertFalse(JwtUtils.isValidJwtStructure(""))
        assertFalse(JwtUtils.isValidJwtStructure("    "))
    }

    @Test
    fun `should return false when the dot structure is broken`() {
        // No dots at all
        assertFalse(JwtUtils.isValidJwtStructure("not_a_jwt_string"))

        // Only 1 dot
        assertFalse(JwtUtils.isValidJwtStructure("abc.def"))

        // JWE format (4 dots) or over-dotted strings
        assertFalse(JwtUtils.isValidJwtStructure("abc.def.ghi.jkl.mno"))
    }

    @Test
    fun `should return false when header is missing the alg property`() {
        val malformedHeader = """{"typ":"JWT"}""" // missing "alg"
        val payloadJson = """{"sub":"123"}"""
        val jwt = "${base64UrlEncode(malformedHeader)}.${base64UrlEncode(payloadJson)}.signature"

        val result = JwtUtils.isValidJwtStructure(jwt)
        assertFalse(result)
    }

    @Test
    fun `should return false when header alg property is blank`() {
        val malformedHeader = """{"alg":"","typ":"JWT"}""" // "alg" is blank
        val payloadJson = """{"sub":"123"}"""
        val jwt = "${base64UrlEncode(malformedHeader)}.${base64UrlEncode(payloadJson)}.signature"

        val result = JwtUtils.isValidJwtStructure(jwt)
        assertFalse(result)
    }

    @Test
    fun `should return false when payload segment is not valid JSON`() {
        val headerJson = """{"alg":"ES256"}"""
        val badPayload = "This is definitely raw text, not a JSON object string"
        val jwt = "${base64UrlEncode(headerJson)}.${base64UrlEncode(badPayload)}.signature"

        val result = JwtUtils.isValidJwtStructure(jwt)
        assertFalse(result)
    }

    @Test
    fun `should return false when base64 segments contain invalid url characters`() {
        // Using characters invalid in a standard base64url string (like spaces)
        val nonBase64UrlHeader = "eyJh bGciOiJSUzI1NiJ9"
        val payloadJson = """{"sub":"123"}"""
        val jwt = "$nonBase64UrlHeader.${base64UrlEncode(payloadJson)}.signature"

        val result = JwtUtils.isValidJwtStructure(jwt)
        assertFalse(result)
    }
}