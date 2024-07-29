package com.ewc.eudi_wallet_oidc_android.services.credentialValidation

import com.ewc.eudi_wallet_oidc_android.services.exceptions.ExpiryException
import com.ewc.eudi_wallet_oidc_android.services.exceptions.SignatureException

class CredentialValidator:CredentialValidatorInterface {

    /**
     * Validates a JWT credential by checking its expiration and signature.
     *
     * @param jwt
     * @param jwksUri
     * @return
     *
     * Returns true if the JWT is valid; otherwise, throws IllegalArgumentException with appropriate messages.
     */
    @Throws(IllegalArgumentException::class)
    override suspend fun validateCredential(jwt: String?, jwksUri: String?): Boolean {
        try {
            // Check if the JWT has expired
            ExpiryValidator().isJwtExpired(jwt = jwt)

            // Validate the JWT signature using the provided JWKS URI
            SignatureValidator().validateSignature(jwt = jwt, jwksUri = jwksUri)

            // If both checks pass, return true indicating the credential is valid
            return true
        } catch (expiryException: ExpiryException) {
            // Throw IllegalArgumentException if JWT is expired
            throw IllegalArgumentException("JWT token expired")
        } catch (signatureException: SignatureException) {
            // Throw IllegalArgumentException if JWT signature is invalid
            throw IllegalArgumentException("JWT signature invalid")
        }
    }
}
