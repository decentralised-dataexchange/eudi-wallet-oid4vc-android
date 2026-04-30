package com.ewc.eudi_wallet_oidc_android.services.utils

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.util.Date
import java.util.UUID

class DPoPProofService {

    private val TAG = "DPoPProofService"

    /**
     * Generates a DPoP Proof JWT with an internal fresh EC Key.
     * * @param httpMethod The HTTP method (e.g., "POST")
     * @param targetUri The full Token Endpoint URL
     * @return Serialized JWT string or null if generation fails
     */
    fun generateDPoP(
        httpMethod: String,
        targetUri: String,
        dpopKey: ECKey?,
        claims: Map<String, Any>? = null
    ): String? {
        return try {
            val header = JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType("dpop+jwt"))
                .jwk(dpopKey?.toPublicJWK())
                .build()

            val claimsBuilder = JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("htm", httpMethod.uppercase())
                .claim("htu", targetUri)
                .issueTime(Date())

            claims?.forEach { (key, value) ->
                claimsBuilder.claim(key, value)
            }

            val signedJWT = SignedJWT(header, claimsBuilder.build())
            signedJWT.sign(ECDSASigner(dpopKey))
            signedJWT.serialize()
        } catch (e: Exception) {
            null
        }
    }

    fun computeAccessTokenHash(token: String?): String {
        if (token == null) return ""
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(token.toByteArray(Charsets.US_ASCII))
        return android.util.Base64.encodeToString(
            hash,
            android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP
        )
    }
}