package com.ewc.eudi_wallet_oidc_android.services.codeVerifier

import com.nimbusds.jose.util.Base64URL
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom

class CodeVerifierService : CodeVerifierServiceInterface {

    /**
     * To generate the code verifier for issuance
     * high-entropy cryptographic random STRING using the
     *    unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
     *    with a minimum length of 43 characters
     *    and a maximum length of 128 characters.
     *    Refer - https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
     * @return code_verifier
     */
    override fun generateCodeVerifier(): String {
        val allowedCharacters =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"

        val minLength = 44 // Minimum length required (exclusive)

        val maxLength = 128 // Maximum length required (exclusive)

        val length = minLength + SecureRandom().nextInt(maxLength - minLength)

        val random = SecureRandom()
        val stringBuilder: StringBuilder = StringBuilder(length)

        for (i in 0 until length) {
            val randomIndex: Int = random.nextInt(allowedCharacters.length)
            val randomChar: Char = allowedCharacters[randomIndex]
            stringBuilder.append(randomChar)
        }

        return stringBuilder.toString()
    }

    /**
     * To generate the code challenge from the code verifier
     * Refer - https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
     * @param codeVerifier
     * @return code_challenge
     */
    override fun generateCodeChallenge(codeVerifier: String): String? {
        try {
            val messageDigest: MessageDigest = MessageDigest.getInstance("SHA-256")
            val hashBytes: ByteArray =
                messageDigest.digest(codeVerifier.toByteArray(StandardCharsets.UTF_8))
            return Base64URL.encode(hashBytes).toString()
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
        }
        return null
    }
}