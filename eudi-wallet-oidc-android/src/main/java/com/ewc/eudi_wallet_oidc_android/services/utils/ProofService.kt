package com.ewc.eudi_wallet_oidc_android.services.utils

import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.models.Credentials
import com.ewc.eudi_wallet_oidc_android.models.IssuerWellKnownConfiguration
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.util.Date

class ProofService {
    fun createProof(
        did: String?,
        subJwk: JWK?,
        nonce: String?,
        issuerConfig: IssuerWellKnownConfiguration?,
        credentialOffer: CredentialOffer?,
    ): String {
        val credentialsSupported = issuerConfig?.credentialsSupported as? Map<String, Any>
        val credentials = credentialOffer?.credentials
        val bindingMethod: String? = when (credentialsSupported) {
            is Map<*, *> -> {
                @Suppress("UNCHECKED_CAST")
                val map = credentialsSupported as? Map<String, Any>
                getCryptographicBindingMethodsSupported(map, credentials)
            }

            else -> null
        }

        // Add claims
        val claimsSet = JWTClaimsSet
            .Builder()
            .issueTime(Date())
            .expirationTime(Date(Date().time + 86400))
            .issuer(did)
            .audience(issuerConfig?.credentialIssuer ?: "")
            .claim("nonce", nonce).build()

        // Add header
        val jwsHeader = JWSHeader
            .Builder(if (subJwk is OctetKeyPair) JWSAlgorithm.EdDSA else JWSAlgorithm.ES256)
            .type(JOSEObjectType("openid4vci-proof+jwt"))
            .keyID(generateKeyId(bindingMethod,subJwk,did))
            .build()


        // Sign with private EC key
        val jwt = SignedJWT(
            jwsHeader, claimsSet
        )
        jwt.sign(
            if (subJwk is OctetKeyPair) Ed25519Signer(subJwk as OctetKeyPair) else ECDSASigner(
                subJwk as ECKey
            )
        )
        return jwt.serialize()
    }
    private fun generateKeyId(bindingMethod: String?, subJwk: JWK?, did: String?): String {
        return when (bindingMethod) {
            "did:jwk" -> {
                val processedDidJwk = subJwk?.let { createDidJwk(it.toJSONString()) }
                processedDidJwk ?: ""
            }

            else -> {
                "$did#${did?.replace("did:key:", "")}"
            }
        }
    }

    private fun createDidJwk(jwk: String?): String {
        val encodedJwk = Base64URL.encode(jwk).toString()
        return "did:jwk:$encodedJwk"
    }

    private fun getCryptographicBindingMethodsSupported(
        credentialsSupported: Map<String, Any>?,
        credentials: ArrayList<Credentials>?
    ): String? {
        if (credentialsSupported.isNullOrEmpty() || credentials.isNullOrEmpty()) {
            return null
        }

        // Extract the first credential type from the credentials list
        val credentialType = credentials.getOrNull(0)?.types?.firstOrNull() as? String ?: return null
        // Find the matching credential in the credentialsSupported map
        val matchingCredentialMap = credentialsSupported[credentialType] as? Map<String, Any>
        val matchingCredential = matchingCredentialMap?.let { CredentialMetaDataConverter().convertToCredentialDetails(it) }

        return matchingCredential?.cryptographicBindingMethodsSupported?.getOrNull(0)
    }
}