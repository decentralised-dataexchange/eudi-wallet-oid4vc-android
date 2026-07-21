package com.ewc.eudi_wallet_oidc_android.services.trust

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.models.TrustServiceProvider
import com.ewc.eudi_wallet_oidc_android.services.utils.CborUtils
import com.ewc.eudi_wallet_oidc_android.services.utils.X509SkiGeneratorHelper
import com.nimbusds.jose.JWSObject
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.util.Base64

object TrustEvaluator {
    @Suppress("TooGenericExceptionCaught")
     suspend fun findTrustedX5c(
        jwt: String?,
        jwksUri: String?,
        trustedAuthoritiesUrls: List<String>? = null,
        trustProvidersList: List<TrustServiceProvider>? = null,
        isDCQLVerificationFlow: Boolean = false
    ): String? {
        val separator = "##SEP##"
         val hasProvidersList = !trustProvidersList.isNullOrEmpty()
         val urls = trustedAuthoritiesUrls ?: emptyList()

        // 1. Check x5c from JWT header
         val x5cList = extractX5cFromJwt(jwt)
         x5cList?.forEach { x5c ->
             // Preference 1: Cache list
             if (hasProvidersList && isTrusted(x5c, trustProvidersList = trustProvidersList, isDCQLVerificationFlow = isDCQLVerificationFlow)) {
                 return x5c
             }
             // Preference 2: Network URLs
             for (url in urls) {
                 if (isTrusted(x5c, url = url, isDCQLVerificationFlow = isDCQLVerificationFlow)) return x5c
             }
         }

         // 2. Fallback to kid + jwksUri
         val kid = extractKidOrDidFromJwt(jwt)
         if (!kid.isNullOrBlank()) {
             val combinedKey = "$kid$separator$jwksUri"

             // Preference 1: trustProvidersList
             if (hasProvidersList) {
                 if (!jwksUri.isNullOrBlank() && isTrusted(combinedKey, trustProvidersList = trustProvidersList, isDCQLVerificationFlow = isDCQLVerificationFlow)) {
                     return combinedKey
                 }
                 if (isTrusted(kid, trustProvidersList = trustProvidersList, isDCQLVerificationFlow = isDCQLVerificationFlow)) {
                     return kid
                 }
             }

             // Preference 2: Network URLs
             for (url in urls) {
                 if (!jwksUri.isNullOrBlank() && isTrusted(combinedKey, url = url, isDCQLVerificationFlow = isDCQLVerificationFlow)) {
                     return combinedKey
                 }
                 if (isTrusted(kid, url = url, isDCQLVerificationFlow = isDCQLVerificationFlow)) return kid
             }
         }

         // 3. Fallback to x5c extracted from COSE
         val coseList = try {
             CborUtils.extractX5CFromCoseBase64(jwt ?: "")
         } catch (e: Exception) {
             Log.e("TrustListUtils", "Error extracting x5c from COSE: ${e.message}")
             emptyList()
         }

        if (coseList.isNotEmpty()) {
            coseList.forEach { x5c ->
                // Preference 1: trustProvidersList
                if (hasProvidersList && isTrusted(x5c, trustProvidersList = trustProvidersList, isDCQLVerificationFlow = isDCQLVerificationFlow)) {
                    return x5c
                }
                // Preference 2: Network URLs
                for (url in urls) {
                    if (isTrusted(x5c, url = url, isDCQLVerificationFlow = isDCQLVerificationFlow)) return x5c
                }
            }
        }else{
            val (kid, did) = CborUtils.extractKidOrDidFromCoseBase64(jwt ?: "")

            val identifier = did ?: kid

            if (identifier != null) {
                if (hasProvidersList && isTrusted(identifier, trustProvidersList = trustProvidersList, isDCQLVerificationFlow = isDCQLVerificationFlow)) {
                    return identifier
                }
                for (url in urls) {
                    if (isTrusted(identifier, url = url, isDCQLVerificationFlow = isDCQLVerificationFlow)) return identifier
                }
            }
        }

        return null
    }


    /**
     * The trust mechanism used to decide whether an issuer/verifier is trusted.
     *
     * The SDK ships two interchangeable implementations of [TrustMechanismInterface]; swap the one
     * returned here to change the trust source everywhere trust is evaluated:
     *
     *  - [ServerTrustMechanismService] (default) — queries the OWS Trust List backend
     *    (POST {baseUrl}/trust-list/lookup). Open endpoint, no device auth. Set the base URL via
     *    [ServerTrustMechanismService.init].
     *  - [TrustMechanismService] — matches the identifier against the local/static EU TSL XML trust
     *    list (the cached [TrustServiceProvider] list first, then the configured trust-list URLs).
     *
     * To use the local trust list instead of the server, change the body to:
     *      TrustMechanismService()
     *
     * To plug in a custom trust source, implement [TrustMechanismInterface] and return it here — the
     * rest of the trust flow ([isTrusted] / [findTrustedX5c]) is implementation-agnostic. Both bundled
     * implementations are no-arg constructable, so swapping is a one-line change.
     */
    private fun trustMechanism(): TrustMechanismInterface = ServerTrustMechanismService()

     suspend fun isTrusted(
         x5cCert: String?,
         url: String? = null,
         trustProvidersList: List<TrustServiceProvider>? = null,
         isDCQLVerificationFlow: Boolean = false
     ): Boolean {
        x5cCert ?: return false
        return trustMechanism().isIssuerOrVerifierTrusted(url, x5cCert, trustProvidersList, isDCQLVerificationFlow)
    }

     fun extractBase64PublicKeyFromX5C(x5cBase64: String): String? {
        try {
            val certBytes = Base64.getDecoder().decode(x5cBase64)
            val certFactory = CertificateFactory.getInstance("X.509")
            val cert = certFactory.generateCertificate(ByteArrayInputStream(certBytes))

            val publicKey = cert.publicKey
            val publicKeyEncoded = publicKey.encoded

            return Base64.getEncoder().encodeToString(publicKeyEncoded)
        } catch (e: Exception) {
            Log.e("TrustListUtils", "Error extracting public key from x5c: ${e.message}")
            return null
        }

    }

     fun extractX5cFromJwt(jwt: String?): List<String>? {
        jwt ?: return null

        return try {
            val jwsObject = JWSObject.parse(jwt)
            val header = jwsObject.header
            val headerJson = header.toJSONObject()
            val x5cArray = headerJson["x5c"] as? List<*>
            x5cArray?.mapNotNull { it as? String }
        } catch (e: Exception) {
            Log.e("JWT Utils", "Failed to extract x5c list from JWT: ${e.message}")
            null
        }
    }

     fun extractKidOrDidFromJwt(jwt: String?): String? {
        jwt ?: return null

        return try {
            val jwsObject = JWSObject.parse(jwt)
            val headerJson = jwsObject.header.toJSONObject()
            headerJson["kid"] as? String
        } catch (e: Exception) {
            Log.e("JWT Utils", "Failed to extract kid from JWT: ${e.message}")
            null
        }
    }
}