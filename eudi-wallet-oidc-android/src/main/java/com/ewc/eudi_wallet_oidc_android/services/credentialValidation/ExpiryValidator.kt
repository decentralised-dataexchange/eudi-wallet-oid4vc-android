package com.ewc.eudi_wallet_oidc_android.services.credentialValidation

import com.ewc.eudi_wallet_oidc_android.services.exceptions.ExpiryException
import com.nimbusds.jwt.SignedJWT
import java.text.ParseException
import java.util.Date

class ExpiryValidator {
    /**
     * Checks if the provided JWT (JSON Web Token) has expired.
     *
     * @param jwt
     * @return
     *
     * Returns true if the JWT is expired, false otherwise.
     * Throws ExpiryException if parsing the JWT or checking expiration encounters errors.
     */
    @Throws(ExpiryException::class)
    fun isJwtExpired(jwt: String?): Boolean {
        return try {
            val signedJWT = SignedJWT.parse(jwt)
            val expirationTime = signedJWT.jwtClaimsSet.expirationTime

            // return if expiry not present in the JWT
            if (expirationTime == null){
                return false
            }
            expirationTime.before(Date()) ?: throw ExpiryException("JWT token expired")

        } catch (e: ParseException) {
            throw ExpiryException("JWT token expired", e)
        }
    }
}