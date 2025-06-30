package com.ewc.eudi_wallet_oidc_android.services.verification.clientIdSchemeHandling

import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jwt.SignedJWT
import org.json.JSONObject
import kotlin.collections.get

class VerifierAttestationSchemeHandler : ClientIdSchemeHandler {
    /**
     * Validates the wrapped presentation request.
     *
     * Validation steps:
     * 1. Checks if the request JWT string is present.
     * 2. Extracts the verifier attestation JWT from the JOSE header of the request.
     * 3. Extracts the confirmation (cnf) public key (JWK) from the verifier attestation JWT.
     * 4. Verifies the signature on the request JWT using the extracted JWK.
     *
     * If any validation step fails, returns a wrapped request containing an appropriate
     * error response.
     *
     * @param wrappedPresentationRequest The wrapped presentation request to validate.
     * @return The original wrapped request if validation succeeds; otherwise,
     *         a wrapped request containing an error response.
     */
    override suspend fun validate(wrappedPresentationRequest: WrappedPresentationRequest): WrappedPresentationRequest {
        if (wrappedPresentationRequest.presentationRequest?.request.isNullOrBlank()) {
            return WrappedPresentationRequest(
                presentationRequest = null,
                errorResponse = ErrorResponse(
                    error = null,
                    errorDescription = "Missing JWT response string"
                )
            )
        }
        val verifierAttestationJwt =
            extractAttestationFromJoseHeader(wrappedPresentationRequest.presentationRequest?.request)
                ?: return WrappedPresentationRequest(
                    presentationRequest = null,
                    errorResponse = ErrorResponse(
                        error = null,
                        errorDescription = "Missing verifier attestation JWT in JOSE header"
                    )
                )

        val cnfJwk = extractCnfPublicKey(verifierAttestationJwt)
            ?: return WrappedPresentationRequest(
                presentationRequest = null,
                errorResponse = ErrorResponse(
                    error = null,
                    errorDescription = "Missing cnf public key in verifier attestation JWT"
                )
            )

        val isSignatureValid =
            verifySignature(wrappedPresentationRequest.presentationRequest?.request, cnfJwk)

        //TODO: The Wallet MUST validate the signature on the Verifier attestation JWT. The iss claim value of the Verifier Attestation JWT MUST identify a party the Wallet trusts for issuing Verifier Attestation JWTs. If the Wallet cannot establish trust, it MUST refuse the request. If the issuer of the Verifier Attestation JWT adds a redirect_uris claim to the attestation, the Wallet MUST ensure the redirect_uri request parameter value exactly matches one of the redirect_uris claim entries.
        //https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID3.html#section-5.10

        if (!isSignatureValid) {
            return WrappedPresentationRequest(
                presentationRequest = null,
                errorResponse = ErrorResponse(
                    error = null,
                    errorDescription = "Invalid signature on request JWT"
                )
            )
        }

        return wrappedPresentationRequest
    }

    /**
     * Updates the wrapped presentation request.
     *
     * No update logic is currently implemented for the Verifier Attestation scheme,
     * so this method returns the request unmodified.
     *
     * @param wrappedPresentationRequest The wrapped presentation request to update.
     * @return The same wrapped presentation request without modifications.
     */
    override fun update(wrappedPresentationRequest: WrappedPresentationRequest): WrappedPresentationRequest {
        return wrappedPresentationRequest
    }

    /**
     * Extracts the verifier attestation JWT from the JOSE header of the request JWT string.
     *
     * Looks for a custom "jwt" parameter in the JOSE header and parses it as a SignedJWT.
     *
     * @param jwtString The JWT string containing the JOSE header.
     * @return The parsed verifier attestation [SignedJWT] if present; otherwise null.
     */
    private fun extractAttestationFromJoseHeader(jwtString: String?): SignedJWT? {
        if (jwtString.isNullOrBlank()) return null

        return try {
            val signedJwt = SignedJWT.parse(jwtString)
            val attestationJwtString = signedJwt.header.getCustomParam("jwt") as? String
            attestationJwtString?.let { SignedJWT.parse(it) }
        } catch (e: Exception) {
            null // Optionally log the error
        }
    }

    /**
     * Extracts the confirmation (cnf) public key (JWK) from the verifier attestation JWT claims.
     *
     * @param attestationJwt The verifier attestation JWT.
     * @return The extracted [JWK] if present; otherwise null.
     */
    private fun extractCnfPublicKey(attestationJwt: SignedJWT): JWK? {
        val claims = attestationJwt.jwtClaimsSet

        // Get the 'cnf' claim as a Map<String, Any> from Nimbus ClaimsSet
        val cnfClaim = claims.getClaim("cnf") as? Map<*, *> ?: return null

        // From 'cnf', get the 'jwk' map
        val jwkMap = cnfClaim["jwk"] as? Map<*, *> ?: return null

        // Convert the map to JSON string
        val jwkJsonString = JSONObject(jwkMap).toString()

        // Parse to Nimbus JWK
        return JWK.parse(jwkJsonString)
    }

    /**
     * Verifies the signature on the JWT string using the provided JWK.
     *
     * Supports EC and RSA key types.
     *
     * @param jwtString The JWT string whose signature is to be verified.
     * @param jwk The public key (JWK) to verify the signature.
     * @return True if the signature is valid; false otherwise.
     */
    private fun verifySignature(jwtString: String?, jwk: JWK): Boolean {
        if (jwtString.isNullOrBlank()) return false

        return try {
            val signedJWT = SignedJWT.parse(jwtString)
            val verifier: JWSVerifier = when (jwk.keyType) {
                KeyType.EC -> ECDSAVerifier(jwk.toECKey())
                KeyType.RSA -> RSASSAVerifier(jwk.toRSAKey())
                else -> return false // Unsupported key type
            }

            signedJWT.verify(verifier)
        } catch (e: Exception) {
            false // Optionally log the exception
        }
    }


}