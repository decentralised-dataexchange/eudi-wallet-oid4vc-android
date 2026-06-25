package com.ewc.eudi_wallet_oidc_android.services.utils

import com.nimbusds.jose.shaded.json.parser.ParseException
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import android.util.Log
import org.json.JSONObject
import java.util.Base64

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
    /**
     * Memory-safe JWT structural validation.
     * Use this instead of [isValidJWT] when the token may be large
     * (e.g. IETF Token Status List JWTs) to avoid OOM in NimbusDS.
     *
     * Does NOT use JWTParser — validates structure and payload JSON
     * manually using only indexOf + Base64 decode on isolated segments.
     */
    fun isValidJwtStructure(token: String?): Boolean {
        if (token.isNullOrBlank()) return false

        return try {
            val firstDot = token.indexOf('.')
            if (firstDot == -1) return false
            val secondDot = token.indexOf('.', firstDot + 1)
            if (secondDot == -1) return false
            val thirdDot = token.indexOf('.', secondDot + 1)
            if (thirdDot != -1) {
                val fourthDot = token.indexOf('.', thirdDot + 1)
                if (fourthDot != -1) return false
            }

            val headerBase64 = token.substring(0, firstDot)
            val headerJson = try {
                String(Base64.getUrlDecoder().decode(headerBase64), Charsets.UTF_8)
            } catch (e: IllegalArgumentException) {
                return false
            }

            val headerObj = JSONObject(headerJson)
            val alg = headerObj.optString("alg", "")
            if (alg.isBlank()) return false

            val payloadBase64 = token.substring(firstDot + 1, secondDot)
            val payloadBytes = try {
                Base64.getUrlDecoder().decode(payloadBase64)
            } catch (e: IllegalArgumentException) {
                return false
            }

            JSONObject(String(payloadBytes, Charsets.UTF_8))

            true

        } catch (e: OutOfMemoryError) {
            Log.e("JwtUtils", "OOM in isValidJWTStructural — token length: ${token.length}")
            false
        } catch (e: Exception) {
            Log.e("JwtUtils", "isValidJWTStructural failed: ${e.message}")
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