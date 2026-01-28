package com.ewc.eudi_wallet_oidc_android.services.utils

import com.nimbusds.jose.shaded.json.parser.ParseException
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT

object JwtUtils {
    fun isValidJWT(token: String?): Boolean {
        if (token.isNullOrBlank()) return false

        return try {
            val jwt: JWT = JWTParser.parse(token)

            when (jwt) {
                is SignedJWT -> {
                    // Signed JWT → payload must not be null
                    jwt.payload != null
                }
                is PlainJWT -> {
                    // Unsigned JWT (alg = none)
                    jwt.payload != null
                }
                else -> false
            }
        } catch (e: Exception) {
            println("JWT parsing failed: ${e.message}")
            false
        }
    }

    @Throws(Exception::class)
    fun parseJWTForPayload(accessToken: String?): String {
        if (accessToken.isNullOrBlank())
            throw Exception("Invalid token!")

        try {
            val jwt: JWT = JWTParser.parse(accessToken)

            val payload = when (jwt) {
                is SignedJWT -> jwt.payload.toString()
                is PlainJWT -> jwt.payload.toString()
                else -> null
            }

            return payload ?: throw Exception("Invalid token!")
        } catch (e: ParseException) {
            throw Exception(e.message ?: "Invalid token!")
        } catch (e: Exception) {
            throw Exception("Invalid token!")
        }
    }
}