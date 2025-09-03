package com.ewc.eudi_wallet_oidc_android.services.utils.trustEvaluator

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.services.rfc012TrustMechanism.TrustMechanismService
import com.ewc.eudi_wallet_oidc_android.services.utils.CborUtils
import com.ewc.eudi_wallet_oidc_android.services.utils.X509SkiGeneratorHelper
import com.nimbusds.jose.JWSObject
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.util.Base64

object TrustEvaluator {
     suspend fun findTrustedX5c(
        jwt: String?,
        jwksUri: String?,
        trustedAuthoritiesUrls: List<String>
    ): String? {
        val separator = "##SEP##"

        // 1. Check x5c from JWT header
        val x5cList = extractX5cFromJwt(jwt)
        x5cList?.forEach { x5c ->
            for (url in trustedAuthoritiesUrls) {
                if (isTrusted(x5c, url)) return x5c
            }
        }

        // 2. Fallback to kid + jwksUri
        val kid = extractKidOrDidFromJwt(jwt)
        if (!kid.isNullOrBlank()) {
            for (url in trustedAuthoritiesUrls) {
                if (!jwksUri.isNullOrBlank() && isTrusted("$kid$separator$jwksUri", url)) {
                    return "$kid$separator$jwksUri"
                }
                if (isTrusted(kid, url)) return kid
            }
        }

        // 3. Fallback to x5c extracted from COSE
        val coseList = try {
            CborUtils.extractX5CFromCoseBase64(jwt ?: "")
        } catch (e: Exception) {
            Log.e("TrustListUtils", "Error extracting x5c from COSE: ${e.message}")
            emptyList()
        }
        coseList.forEach { x5c ->
            for (url in trustedAuthoritiesUrls) {
                if (isTrusted(x5c, url)) return x5c
            }
        }

        return null
    }


     suspend fun isTrusted(x5cCert: String?, url: String): Boolean {
        val trustMechanismService = TrustMechanismService()
        x5cCert ?: return false

        if (trustMechanismService.isIssuerOrVerifierTrusted(url, x5cCert)) return true

        val publicKey = extractBase64PublicKeyFromX5C(x5cCert)
        if (publicKey != null && trustMechanismService.isIssuerOrVerifierTrusted(
                url,
                publicKey
            )
        ) return true

        val cert = X509SkiGeneratorHelper.parseCertificateFromBase64(x5cCert)
        val ski = cert?.let { X509SkiGeneratorHelper.generateSkiString(it) }
        if (ski != null && trustMechanismService.isIssuerOrVerifierTrusted(url, ski)) return true

        return false
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