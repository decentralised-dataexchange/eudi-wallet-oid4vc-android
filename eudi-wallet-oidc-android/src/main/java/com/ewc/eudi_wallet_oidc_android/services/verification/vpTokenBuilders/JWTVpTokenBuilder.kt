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
    override fun build(
        credentialList: List<String>?,
        presentationRequest: PresentationRequest?,
        did: String?,
        jwk: JWK?,
        inputDescriptors: Any?
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

}