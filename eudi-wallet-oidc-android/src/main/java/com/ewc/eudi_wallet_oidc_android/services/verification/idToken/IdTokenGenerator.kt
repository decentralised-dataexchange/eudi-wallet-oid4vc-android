package com.ewc.eudi_wallet_oidc_android.services.verification.idToken

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

class IdTokenGenerator : IdTokenGeneratorInterface {
    override fun generateIdToken(
        presentationRequest: PresentationRequest,
        did: String?,
        subJwk: JWK?
    ): String? {
        val iat = Date()
        val claimsSet = JWTClaimsSet.Builder()
            .issuer(did)
            .subject(did)
            .audience(
                presentationRequest.clientId
                    ?: "https://api-conformance.ebsi.eu/conformance/v3/auth-mock"
            )
            .expirationTime(Date(iat.time + 600000))
            .issueTime(iat)
            .claim("nonce", presentationRequest.nonce)
            .build()
        val jwsHeader =
            JWSHeader.Builder(
                if (subJwk is OctetKeyPair)
                    JWSAlgorithm.EdDSA
                else
                    JWSAlgorithm.ES256
            )
                .type(JOSEObjectType("JWT"))
                .keyID("$did#${did?.replace("did:key:", "")}")
                .jwk(subJwk?.toPublicJWK())
                .build()

        val jwt = SignedJWT(
            jwsHeader,
            claimsSet
        )

        jwt.sign(
            if (subJwk is OctetKeyPair)
                Ed25519Signer(subJwk)
            else
                ECDSASigner(subJwk as ECKey)
        )
        val jwtSerialize = jwt.serialize()
        return jwtSerialize
    }
}