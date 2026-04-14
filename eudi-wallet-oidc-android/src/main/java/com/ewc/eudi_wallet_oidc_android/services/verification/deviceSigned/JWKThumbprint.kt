package com.ewc.eudi_wallet_oidc_android.services.verification.deviceSigned

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL

object JWKThumbprint {

    /**
     * Computes the JWK Thumbprint (RFC 7638) of a [JWK] as raw SHA-256 bytes.
     *
     * This is what the verifier calls `jwk_thumbprint_bytes` — the raw 32-byte
     * SHA-256 digest that goes into OpenID4VPHandoverInfo as a CBOR bstr.
     *
     * Nimbus provides [JWK.computeThumbprint] which returns the thumbprint as a
     * Base64URL string. We decode that back to raw bytes here, matching exactly
     * what the Python verifier does:
     *
     *   padded = jwk_thumbprint + "=" * padding
     *   jwk_thumbprint_bytes = base64.urlsafe_b64decode(padded)
     *
     * @param jwk The JWK whose thumbprint to compute (EC, RSA, OKP, etc.)
     * @return Raw 32-byte SHA-256 thumbprint (bstr for CBOR encoding).
     * @throws JOSEException if the thumbprint cannot be computed.
     */
    fun computeJwkThumbprintBytes(jwk: JWK): ByteArray {
        // Nimbus computes RFC 7638 thumbprint: SHA-256 of canonical JSON members.
        // Returns a Base64URL-encoded string (no padding).
        val thumbprintBase64Url: Base64URL = jwk.computeThumbprint("SHA-256")

        // Decode Base64URL → raw bytes (these are the 32 SHA-256 hash bytes).
        return thumbprintBase64Url.decode()
    }

    /**
     * Convenience overload — returns the thumbprint as a Base64URL [String]
     * (no padding), e.g. for logging or JWK "kid" assignment.
     */
    fun computeJwkThumbprintBase64Url(jwk: JWK): String {
        return jwk.computeThumbprint("SHA-256").toString()
    }
}