package com.ewc.eudi_wallet_oidc_android.services.verification.client

import com.ewc.eudi_wallet_oidc_android.services.verification.request.PresentationRequestException
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jwt.SignedJWT
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.PublicKey
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64

/** The X.509 side of the `x509_*` prefixes: the `x5c` header, the leaf key, the chain. */
internal object RequestObjectCertificates {

    /** The `x5c` chain, leaf first, or null when the header has none. */
    fun chain(jwt: SignedJWT): List<X509Certificate>? {
        val encoded = jwt.header.x509CertChain?.takeIf { it.isNotEmpty() } ?: return null
        val factory = CertificateFactory.getInstance("X.509")
        return try {
            encoded.map { factory.generateCertificate(ByteArrayInputStream(it.decode())) as X509Certificate }
        } catch (e: Exception) {
            throw PresentationRequestException.ClientNotVerified("the x5c certificate chain could not be read")
        }
    }

    fun verifySignature(jwt: SignedJWT, key: PublicKey): Boolean = try {
        val verifier: JWSVerifier = when (key) {
            is ECPublicKey -> ECDSAVerifier(key)
            is RSAPublicKey -> RSASSAVerifier(key)
            else -> return false
        }
        jwt.verify(verifier)
    } catch (e: Exception) {
        false
    }

    fun verifySignature(jwt: SignedJWT, key: JWK): Boolean = try {
        val verifier: JWSVerifier = when (key.keyType) {
            KeyType.EC -> ECDSAVerifier(key.toECKey())
            KeyType.RSA -> RSASSAVerifier(key.toRSAKey())
            else -> return false
        }
        jwt.verify(verifier)
    } catch (e: Exception) {
        false
    }

    /**
     * Section 5.9.3: "The Wallet MUST validate the signature and the trust chain of the X.509
     * certificate." Every certificate must be within its validity period and signed by the next
     * one in the chain. When [anchors] are given the chain must also end in one of them, and the
     * result is true. Without anchors the chain is only checked for consistency and the result
     * is false: the trust decision then rests with the host.
     *
     * @throws PresentationRequestException.ClientNotVerified
     */
    fun checkChain(chain: List<X509Certificate>, anchors: List<X509Certificate>): Boolean {
        chain.forEach { cert ->
            try {
                cert.checkValidity()
            } catch (e: Exception) {
                throw PresentationRequestException.ClientNotVerified("a certificate in the x5c chain is expired or not yet valid")
            }
        }
        chain.zipWithNext().forEach { (child, parent) ->
            try {
                child.verify(parent.publicKey)
            } catch (e: Exception) {
                throw PresentationRequestException.ClientNotVerified("the x5c certificate chain does not link")
            }
        }
        if (anchors.isEmpty()) return false

        // The anchor itself must not be part of the path handed to the validator.
        val path = chain.filterNot { cert -> anchors.any { it.encoded.contentEquals(cert.encoded) } }
        if (path.isEmpty()) return true
        try {
            val params = PKIXParameters(anchors.map { TrustAnchor(it, null) }.toSet()).apply { isRevocationEnabled = false }
            CertPathValidator.getInstance("PKIX").validate(CertificateFactory.getInstance("X.509").generateCertPath(path), params)
        } catch (e: Exception) {
            throw PresentationRequestException.ClientNotVerified("the x5c certificate chain does not end in a trusted anchor")
        }
        return true
    }

    /** RFC 5280 dNSName entries (type 2). */
    fun dnsNames(cert: X509Certificate): List<String> = sanOfType(cert, 2)

    /** RFC 5280 uniformResourceIdentifier entries (type 6). */
    fun uriNames(cert: X509Certificate): List<String> = sanOfType(cert, 6)

    private fun sanOfType(cert: X509Certificate, type: Int): List<String> =
        cert.subjectAlternativeNames?.mapNotNull { san ->
            (san[1] as? String)?.takeIf { san[0] == type }
        } ?: emptyList()

    /** Section 5.9.3 `x509_hash`: "the base64url-encoded value of the SHA-256 hash of the DER-encoded X.509 certificate". */
    fun sha256Base64Url(cert: X509Certificate): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.encoded))
}
