package com.ewc.eudi_wallet_oidc_android.services.credentialValidation.helperFunctions

import java.io.ByteArrayInputStream
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString as CborByteString
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.UnicodeString as CborUnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessEbsiJWKFromKID
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessJWKFromJwksUri
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessJWKFromKID
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessKeyJWKFromKID
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessTDWFromKID
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessWebJWKFromKID
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.publicKeyExtraction.ProcessWebVhFromKID
import com.nimbusds.jose.JWSAlgorithm
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.OctetKeyPair

suspend fun getValidationKey(issuerAuth: CborArray, jwksUri: String?): PublicKey {
    val unprotectedMap = issuerAuth.dataItems[1] as? CborMap
        ?: throw IllegalArgumentException("Unprotected header missing")

    // 1️⃣ Try Label 33 (x5c / x5chain)
    val x5chainValue = unprotectedMap.get(UnsignedInteger(33))
    if (x5chainValue != null) {
        val certBytes = when (x5chainValue) {
            is CborByteString -> x5chainValue.bytes
            is CborArray -> {
                val dataItem = x5chainValue.dataItems.firstOrNull()
                    ?: throw IllegalArgumentException("Empty x5c array")

                when (dataItem) {
                    is CborByteString -> dataItem.bytes

                    is CborUnicodeString ->
                        java.util.Base64.getDecoder().decode(dataItem.string)

                    else -> throw IllegalArgumentException(
                        "Unsupported x5c entry type: ${dataItem.javaClass}"
                    )
                }
            }

            else -> throw IllegalArgumentException("Unsupported x5chain format")
        }
        val cf = CertificateFactory.getInstance("X.509")
        val cert = cf.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
        cert.checkValidity()
        return cert.publicKey
    }

    // 2️⃣ Try Label 4 (kid)
    val kidValue = unprotectedMap.get(UnsignedInteger(4))
    if (kidValue != null) {
        val kid = when (kidValue) {
            is CborByteString -> String(kidValue.bytes)
            is CborUnicodeString -> kidValue.string
            else -> throw IllegalArgumentException("Unsupported kid format")
        }

        // 2a. Get typed COSE algorithm
        val coseAlg = getCoseAlgorithm(issuerAuth)
        val algorithm = toJwsAlgorithm(coseAlg)

        // 2b. Collect possible JWKs
        val jwkList: MutableList<JWK> = mutableListOf()
        if (kid.startsWith("did:key:z")) ProcessKeyJWKFromKID().processKeyJWKFromKID(kid, algorithm)?.let { jwkList.add(it) }
        if (kid.startsWith("did:ebsi:z")) ProcessEbsiJWKFromKID().processEbsiJWKFromKID(kid)?.let { jwkList.add(it) }
        if (kid.startsWith("did:jwk")) ProcessJWKFromKID().processJWKFromKID(kid)?.let { jwkList.add(it) }
        if (kid.startsWith("did:tdw")) ProcessTDWFromKID().processTrustDIDWebFromKID(kid)?.let { jwkList.add(it) }
        if (kid.startsWith("did:webvh")) ProcessWebVhFromKID().processWebVerifiableHistoryFromKID(kid)?.let { jwkList.add(it) }
        if (kid.startsWith("did:web")) ProcessWebJWKFromKID().processWebJWKFromKID(kid)?.let { jwkList.add(it) }
        if (!jwksUri.isNullOrEmpty()) ProcessJWKFromJwksUri().processJWKFromJwksUri(kid, jwksUri)?.let { jwkList.add(it) }

        if (jwkList.isEmpty()) {
            throw IllegalArgumentException("No JWK could be resolved for kid: $kid")
        }

        // 2c. Pick the first JWK (or implement selection logic)
        val jwk = jwkList.first()

        // 2d. Convert JWK → java.security.PublicKey
        return when (jwk) {
            is ECKey -> jwk.toECPublicKey()
            is OctetKeyPair -> jwk.toPublicKey() // EdDSA
            else -> throw IllegalArgumentException("Unsupported JWK type: ${jwk.javaClass}")
        }
    }

    throw IllegalArgumentException("IssuerAuth missing both x5c (33) and kid (4)")
}


fun toJwsAlgorithm(coseAlg: CoseAlgorithm): JWSAlgorithm =
    when (coseAlg) {
        CoseAlgorithm.ES256 -> JWSAlgorithm.ES256
        CoseAlgorithm.ES384 -> JWSAlgorithm.ES384
        CoseAlgorithm.ES512 -> JWSAlgorithm.ES512
        CoseAlgorithm.EDDSA -> JWSAlgorithm.EdDSA
    }



