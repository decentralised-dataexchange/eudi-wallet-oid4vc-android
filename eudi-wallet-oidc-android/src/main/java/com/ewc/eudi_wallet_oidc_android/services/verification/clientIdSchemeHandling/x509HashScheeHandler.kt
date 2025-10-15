package com.ewc.eudi_wallet_oidc_android.services.verification.clientIdSchemeHandling

import android.util.Base64
import com.ewc.eudi_wallet_oidc_android.models.ErrorResponse
import com.ewc.eudi_wallet_oidc_android.models.WrappedPresentationRequest
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.SignatureValidator
import com.ewc.eudi_wallet_oidc_android.services.exceptions.SignatureException
import com.ewc.eudi_wallet_oidc_android.services.utils.X509SanRequestVerifier
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.cert.TrustAnchor
import java.security.cert.PKIXParameters
import java.security.cert.CertPathValidator

class X509HashSchemeHandler : ClientIdSchemeHandler {

    override suspend fun validate(wrappedPresentationRequest: WrappedPresentationRequest): WrappedPresentationRequest {
        val requestJwt = wrappedPresentationRequest.presentationRequest?.request
            ?: return invalidRequest("Missing request")

        val clientId = wrappedPresentationRequest.presentationRequest?.clientId
            ?: return invalidRequest("Missing client_id")

        if (!clientId.startsWith("x509_hash:")) {
            return invalidRequest("Client ID does not start with x509_hash:")
        }

        // Step 1: Extract x5c chain
        val x5cChain = X509SanRequestVerifier.instance.extractX5cFromJWT(requestJwt)
        if (x5cChain.isNullOrEmpty()) {
            return invalidRequest("x5c chain missing in request")
        }

        return try {
            // Step 2: Decode leaf certificate and compute SHA-256 hash
            val leafBase64 = x5cChain.first()
            val certBytes = Base64.decode(leafBase64, Base64.DEFAULT)

            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(certBytes)
            val base64UrlHash = Base64.encodeToString(hash, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

            val expectedHash = clientId.removePrefix("x509_hash:")
            if (base64UrlHash != expectedHash) {
                return invalidRequest("Client ID hash does not match certificate hash")
            }

            // Step 4: Verify JWT signature using SignatureValidator
            val isSignatureValid = try {
                SignatureValidator().validateSignature(requestJwt, jwksUri = null)
            } catch (e: SignatureException) {
                false
            }

            if (!isSignatureValid) {
                return invalidRequest("JWT signature verification failed using X.509 certificate")
            }

            //  All checks passed
            wrappedPresentationRequest

        } catch (e: Exception) {
            invalidRequest(e.message ?: "Invalid Request")
        }
    }

    override fun update(wrappedPresentationRequest: WrappedPresentationRequest): WrappedPresentationRequest {
        return wrappedPresentationRequest
    }

    private fun invalidRequest(message: String): WrappedPresentationRequest {
        return WrappedPresentationRequest(
            presentationRequest = null,
            errorResponse = ErrorResponse(
                error = null,
                errorDescription = message
            )
        )
    }
}
