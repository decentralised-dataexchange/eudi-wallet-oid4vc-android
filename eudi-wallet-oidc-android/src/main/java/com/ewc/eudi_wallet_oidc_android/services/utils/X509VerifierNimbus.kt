package com.ewc.eudi_wallet_oidc_android.services.utils
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.SignedJWT
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

class X509VerifierNimbus {
    fun verifyJwtWithX5C(jwtString: String): Boolean {
        return try {
            // 1. Parse the JWT
            val signedJWT = SignedJWT.parse(jwtString)

            // 2. Extract the JWS Header
            val header: JWSHeader = signedJWT.header

            // 3. Get the x5c certificate chain from the header
            val x5cList: MutableList<Base64>? = header.x509CertChain

            if (x5cList.isNullOrEmpty()) {
                throw IllegalArgumentException("x5c header is missing or empty")
            }

            // 4. Decode the first certificate
            val certBytes = x5cList[0].decode()
            val certFactory = CertificateFactory.getInstance("X.509")
            val cert =
                certFactory.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate

            // 5. Extract the public key
            val publicKey = cert.publicKey

            // 6. Select appropriate verifier based on key type
            val verifier = when (publicKey.algorithm) {
                "EC" -> ECDSAVerifier(publicKey as ECPublicKey)
                "RSA" -> RSASSAVerifier(publicKey as RSAPublicKey)
                else -> throw IllegalArgumentException("Unsupported key algorithm: ${publicKey.algorithm}")
            }

            // 7. Verify the signature
            signedJWT.verify(verifier)
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }
}
