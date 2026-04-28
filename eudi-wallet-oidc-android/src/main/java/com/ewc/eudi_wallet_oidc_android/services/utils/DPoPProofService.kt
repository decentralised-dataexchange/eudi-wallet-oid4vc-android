package com.ewc.eudi_wallet_oidc_android.services.utils

import android.util.Log
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
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
    fun generateDPoP(httpMethod: String, targetUri: String): String? {
        return try {
            // 1. Generate a fresh P-256 EC KeyPair internally
            // This key contains both Public and Private parts
            val ecKey: ECKey = ECKeyGenerator(Curve.P_256)
                .keyID(UUID.randomUUID().toString())
                .generate()

            // 2. Create the JWS Header
            // We must include the Public Key (JWK) so the server can verify the signature
            val header = JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType("dpop+jwt"))
                .jwk(ecKey.toPublicJWK())
                .build()

            // 3. Create the JWT Payload (Claims)
            val claimsSet = JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString()) // Replay protection
                .claim("htm", httpMethod.uppercase())
                .claim("htu", targetUri)
                // iat: Backdated by 60s for server clock synchronization
                .issueTime(Date(System.currentTimeMillis() - 60000))
                .build()

            // 4. Sign the JWT
            val signedJWT = SignedJWT(header, claimsSet)
            val signer = ECDSASigner(ecKey)
            signedJWT.sign(signer)

            // 5. Serialize
            val result = signedJWT.serialize()
            Log.d(TAG, "New DPoP generated with internal key: $result")

            result

        } catch (e: Exception) {
            Log.e(TAG, "Internal DPoP Generation Failed: ${e.message}")
            null
        }
    }
}