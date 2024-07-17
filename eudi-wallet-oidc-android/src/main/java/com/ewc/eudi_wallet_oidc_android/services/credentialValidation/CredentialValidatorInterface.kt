package com.ewc.eudi_wallet_oidc_android.services.credentialValidation

interface CredentialValidatorInterface {
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
    suspend fun  validateCredential(jwt: String?,jwksUri:String?):Boolean
}