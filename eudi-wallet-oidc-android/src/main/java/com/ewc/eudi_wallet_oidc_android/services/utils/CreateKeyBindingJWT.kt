package com.ewc.eudi_wallet_oidc_android.services.utils

import android.util.Log
import com.ewc.eudi_wallet_oidc_android.services.sdjwt.SDJWTService
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.util.Date
import java.util.UUID

fun createKeyBindingJWT(
    aud: String?,
    credential: String,
    subJwk: JWK?,
    claims: Map<String, Any>?,
    nonce: String?,
    responseMode: String? = null,
    amr: List<Map<String, String>>? = null
): String? {
    try {
        // Start building the JWT claims
        val claimsSetBuilder = JWTClaimsSet.Builder()
            .claim("nonce",nonce ?: UUID.randomUUID().toString())
            .claim("aud", aud)
            .claim("iat", Date())
            .claim("sd_hash", SDJWTService().calculateSHA256Hash(credential))
            .claim("jti", UUID.randomUUID().toString())

        // ✅ Add response_mode only if provided
        responseMode?.let {
            claimsSetBuilder.claim("response_mode", it)
        }

        // ✅ Add amr only if provided
        amr?.let {
            claimsSetBuilder.claim("amr", it)
        }

        // If claims are provided, add them to the claims set
        claims?.forEach { (key, value) ->
            claimsSetBuilder.claim(key, value)
        }

        // Build the claims set
        val claimsSet = claimsSetBuilder.build()
        Log.d("processToken:", "createKeyBindingJWT claimsSet value = ${claimsSet.toJSONObject()}")

        // Create JWT header
        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("kb+jwt"))
            .build()

        // Sign the JWT
        val signedJWT = SignedJWT(header, claimsSet)

        // Create signer with the private key
        if (subJwk is ECKey) {
            Log.d("processToken:", "subJwk private key = ${subJwk.toPrivateKey()}")
        }
        else{
            Log.d("processToken:", "subJwk type = ${subJwk?.javaClass?.name}")

        }
        val signer = ECDSASigner(subJwk as ECKey)

        // Sign the JWT
        signedJWT.sign(signer)
        Log.d("processToken:","createKeyBindingJWT signedJWT returned successfully")
        // Return the serialized JWT
        return signedJWT.serialize()


    } catch (e: Exception) {
        Log.d("processToken:", "createKeyBindingJWT signedJWT error ${e.message.toString()}")
        return null
    }
}