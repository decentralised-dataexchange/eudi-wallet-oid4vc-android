package com.ewc.eudi_wallet_oidc_android.services.verification.vpTokenBuilders

import com.ewc.eudi_wallet_oidc_android.models.InputDescriptors
import com.ewc.eudi_wallet_oidc_android.models.PresentationRequest
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.util.Date
import java.util.UUID

class JWTVpTokenBuilder: VpTokenBuilder {
    companion object {
        private const val JWT_EXPIRATION_MS = 600_000L // 10 minutes
    }
    override suspend fun build(
        credentialList: List<String>?,
        presentationRequest: PresentationRequest?,
        did: String?,
        jwk: JWK?,
        inputDescriptors: Any?,
        isScaFlow: Boolean
    ): String? {
        val iat = Date()
        val jti = "urn:uuid:${UUID.randomUUID()}"
        val claimsSet = JWTClaimsSet.Builder()
            .audience(presentationRequest?.clientId)
            .issueTime(iat)
            .expirationTime(Date(iat.time + 600000))
            .issuer(did)
            .jwtID(jti)
            .notBeforeTime(iat)
            .claim("nonce", presentationRequest?.nonce)
            .subject(did)
            .claim(
                "vp", com.nimbusds.jose.shaded.json.JSONObject(
                    hashMapOf(
                        "@context" to listOf("https://www.w3.org/2018/credentials/v1"),
                        "holder" to did,
                        "id" to jti,
                        "type" to listOf("VerifiablePresentation"),
                        "verifiableCredential" to credentialList
                    )
                )
            )
            .build()

        val jwsHeader =
            JWSHeader.Builder(
                if (jwk is OctetKeyPair)
                    JWSAlgorithm.EdDSA
                else
                    JWSAlgorithm.ES256
            )
                .type(JOSEObjectType("JWT"))
                .keyID("$did#${did?.replace("did:key:", "")}")
                .jwk(jwk?.toPublicJWK())
                .build()

        val jwt = SignedJWT(
            jwsHeader,
            claimsSet
        )

        jwt.sign(
            if (jwk is OctetKeyPair)
                Ed25519Signer(jwk)
            else
                ECDSASigner(jwk as ECKey)
        )
        val jwtSerialize = jwt.serialize()

        return jwtSerialize
    }

    override suspend fun buildV2(
        credentialList: List<String>?,
        presentationRequest: PresentationRequest?,
        did: String?,
        jwk: JWK?,
        inputDescriptors: Any?,
        isScaFlow: Boolean,
        jwkList: List<JWK?>?
    ): List<String?> {
        if (credentialList.isNullOrEmpty()) return emptyList()

        val results = mutableListOf<String?>()

        credentialList.forEachIndexed { index, individualCredential ->
            val credentialJwk = jwkList?.getOrNull(index) ?: jwk
            val credentialDid = credentialJwk?.let {
                "did:key:${it.toECKey().toPublicJWK().computeThumbprint()}"
            } ?: did
            val iat = Date()
            val jti = "urn:uuid:${UUID.randomUUID()}"
            // 2. Build claims for a single-credential VP
            val claimsSet = JWTClaimsSet.Builder()
                .audience(presentationRequest?.clientId)
                .issueTime(iat)
                .expirationTime(Date(iat.time + JWT_EXPIRATION_MS))
                .issuer(credentialDid)
                .jwtID(jti)
                .notBeforeTime(iat)
                .claim("nonce", presentationRequest?.nonce)
                .subject(credentialDid)
                .claim(
                    "vp", com.nimbusds.jose.shaded.json.JSONObject(
                        hashMapOf(
                            "@context" to listOf("https://www.w3.org/2018/credentials/v1"),
                            "holder" to credentialDid,
                            "id" to jti,
                            "type" to listOf("VerifiablePresentation"),
                            "verifiableCredential" to listOf(individualCredential) // Only one here
                        )
                    )
                )
                .build()
            // 3. Create Header using the specific key
            val jwsHeader = JWSHeader.Builder(
                if (credentialJwk is OctetKeyPair) JWSAlgorithm.EdDSA else JWSAlgorithm.ES256
            )
                .type(JOSEObjectType("JWT"))
                // Ensure the kid matches the key used for this credential
                .keyID("$credentialDid#${credentialDid?.replace("did:key:", "")}")
                .jwk(credentialJwk?.toPublicJWK())
                .build()

            val jwt = SignedJWT(jwsHeader, claimsSet)

            // 4. Sign using the specific private key
            jwt.sign(
                if (credentialJwk is OctetKeyPair)
                    Ed25519Signer(credentialJwk)
                else
                    ECDSASigner(credentialJwk as ECKey)
            )

            results.add(jwt.serialize())
        }
        return results
    }

}