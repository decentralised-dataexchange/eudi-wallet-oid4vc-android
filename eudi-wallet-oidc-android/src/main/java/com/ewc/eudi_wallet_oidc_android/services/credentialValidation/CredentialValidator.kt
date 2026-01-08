package com.ewc.eudi_wallet_oidc_android.services.credentialValidation

import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.helperFunctions.getValidationKey
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.helperFunctions.verifyCoseSignature
import com.ewc.eudi_wallet_oidc_android.services.exceptions.ExpiryException
import com.ewc.eudi_wallet_oidc_android.services.exceptions.SignatureException
import com.ewc.eudi_wallet_oidc_android.services.utils.CborUtils

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
    override suspend fun validateCredential(jwt: String?,
                                            jwksUri: String?,
                                            format: String?): Boolean {
        if (format == "mso_mdoc") {
            try {
                // 1. Extract the IssuerAuth (COSE_Sign1 structure)
                val issuerAuth = CborUtils.processExtractIssuerAuth(listOf(jwt))
                if (issuerAuth.dataItems.isEmpty()) {
                    throw IllegalArgumentException("Invalid mDoc: IssuerAuth structure is missing")
                }

                // 2. Resolve the Public Key (Handling 33: x5c or 4: kid)
                val publicKey = getValidationKey(issuerAuth, jwksUri)

                // 3. Verify the cryptographic COSE signature
                verifyCoseSignature(issuerAuth, publicKey)

                return true
            } catch (e: Exception) {
                if (e is IllegalArgumentException) throw e
                throw IllegalArgumentException("mso_mdoc validation failed: ${e.localizedMessage}")
            }
        }
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
            throw IllegalArgumentException(signatureException.message ?: "JWT signature invalid")
        }
    }
}