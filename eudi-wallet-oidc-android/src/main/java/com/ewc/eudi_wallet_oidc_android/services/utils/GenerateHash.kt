package com.ewc.eudi_wallet_oidc_android.services.utils

import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.Base64

fun generateHash(input: String): String? {
    return try {
        // Get the MessageDigest instance
        val digest = MessageDigest.getInstance("SHA-256")

        // Calculate the hash
        // Note: Per requirements, we hash the string directly without decoding it first.
        val hashBytes = digest.digest(input.toByteArray(Charsets.UTF_8))

        // 4. Encode to Base64URL without padding
        Base64.getUrlEncoder().withoutPadding().encodeToString(hashBytes)
    } catch (e: NoSuchAlgorithmException) {
        throw RuntimeException("SHA-256 algorithm not found!", e)
    }
}