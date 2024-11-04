package com.ewc.eudi_wallet_oidc_android.services.utils

import com.nimbusds.jose.shaded.json.parser.ParseException
import com.nimbusds.jwt.SignedJWT

object JwtUtils {
    fun isValidJWT(token: String?): Boolean {
        if (token.isNullOrBlank())
            return false
        try {
            // Parse the JWT token
            val parsedJWT = SignedJWT.parse(token)
            return parsedJWT.payload != null
        } catch (e: Exception) {
            println("JWT parsing failed: ${e.message}")
            return false
        }
    }

    @Throws(ParseException::class)
    fun parseJWTForPayload(accessToken: String?): String {
        if (accessToken.isNullOrBlank())
            throw java.lang.Exception("Invalid token!")
        try {
            val decodedJWT = SignedJWT.parse(accessToken)
            return decodedJWT.payload.toString()
        } catch (e: ParseException) {
            throw java.lang.Exception(e.message ?: "Invalid token!")
        } catch (e: Exception){
            throw java.lang.Exception("Invalid token!")
        }
    }
}