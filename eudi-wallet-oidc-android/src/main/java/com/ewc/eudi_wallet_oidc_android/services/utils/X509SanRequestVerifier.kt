package com.ewc.eudi_wallet_oidc_android.services.utils

import android.util.Base64
import com.ewc.eudi_wallet_oidc_android.services.verification.ClientIdScheme
import com.ewc.eudi_wallet_oidc_android.services.verification.clientIdSchemeHandling.ClientIdParser
import com.nimbusds.jose.JWSAlgorithm
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import java.util.Base64 as base64

class X509SanRequestVerifier private constructor() {

    companion object {
        val instance = X509SanRequestVerifier()
    }

    fun extractX5cFromJWT(jwt: String): List<String>? {
        val segments = jwt.split(".")
        if (segments.size != 3) {
            println("Invalid JWT format")
            return null
        }

        val headerSegment = segments[0]
        val headerJson = String(Base64.decode(headerSegment, Base64.URL_SAFE))
        val headerMap = JSONObject(headerJson)
        return if (headerMap.has("x5c")) {
            val x5cArray = headerMap.getJSONArray("x5c")
            List(x5cArray.length()) { x5cArray.getString(it) }
        } else {
            println("x5c not found in JWT header")
            null
        }
    }

//    fun validateClientIDInCertificate(x5cChain: List<String>?, clientID: String?): Boolean {
//        val leafCertData = Base64.decode(x5cChain?.firstOrNull() ?: "", Base64.DEFAULT)
//        val certificate = CertificateFactory.getInstance("X.509")
//            .generateCertificate(leafCertData.inputStream()) as X509Certificate
//
//        val dnsNames = extractDNSNamesFromCertificate(certificate)
//        return dnsNames.contains(clientID)
//    }

    private fun extractDNSNamesFromCertificate(certificate: X509Certificate): List<String> {
        val dnsNames = mutableListOf<String>()
        val sanList = certificate.subjectAlternativeNames ?: return dnsNames

        for (san in sanList) {
            if (san[0] == 2) { // DNS Name
                dnsNames.add(san[1] as String)
            }
        }
        return dnsNames
    }

    fun validateSignatureWithCertificate(
        jwt: String,
        x5cChain: List<String>,
        algorithm: JWSAlgorithm? = null
    ): Boolean {
        return try {
            // Decode the leaf certificate from the x5cChain
            val leafCertData = Base64.decode(x5cChain.firstOrNull() ?: "", Base64.DEFAULT)
            val certificate = CertificateFactory.getInstance("X.509")
                .generateCertificate(leafCertData.inputStream()) as X509Certificate
            val publicKey = certificate.publicKey

            // Split JWT into its segments
            val segments = jwt.split(".")
            if (segments.size != 3) {
                println("Invalid JWT format")
                return false
            }

            val signedData = "${segments[0]}.${segments[1]}"

            val signatureWithoutTilda = if (segments[2].contains("~")) {
                // If the signature contains '~', split it and take the first part
                segments[2].split("~")[0]
            } else {
                // If there's no '~', assign the signature as is
                segments[2]
            }

            val signature: ByteArray =

//                if (algorithm != null && algorithm.name.startsWith("ES")) {
                convertRawSignatureToASN1DER(
                    // Base64.decode(segments[2], Base64.DEFAULT)
                    Base64.decode(base64UrlToBase64(signatureWithoutTilda), Base64.DEFAULT)
                ) ?: return false
//            } else {
//                Base64.decode(base64UrlToBase64(signatureWithoutTilda), Base64.DEFAULT)
//            }

            // Validate signature before verifying
            if (signature.isEmpty()) {
                println("Signature is invalid")
                return false
            }


            // Verify the signature
            verifySignature(publicKey, signedData.toByteArray(), signature,algorithm)
        } catch (e: Exception) {
            println("Error during signature validation: ${e.message}")
            false // Return false in case of an exception
        }
    }

    private fun convertRawSignatureToASN1DER(rawSignature: ByteArray): ByteArray? {
        return try {
            val halfLength = rawSignature.size / 2
            val r = rawSignature.sliceArray(0 until halfLength)
            val s = rawSignature.sliceArray(halfLength until rawSignature.size)

            fun asn1Length(length: Int): ByteArray {
                return if (length < 128) {
                    byteArrayOf(length.toByte())
                } else {
                    val lengthBytes = length.toBigInteger().toByteArray()
                    val trimmedLengthBytes = lengthBytes.dropWhile { it == 0.toByte() }.toByteArray()
                    byteArrayOf((0x80 or trimmedLengthBytes.size).toByte()) + trimmedLengthBytes
                }
            }

            fun asn1Integer(data: ByteArray): ByteArray {
                var bytes = data.toList()
                // Add a leading zero if the MSB is set (to avoid it being interpreted as negative)
                if (bytes.isNotEmpty() && (bytes[0].toInt() and 0x80) != 0) {
                    bytes = listOf(0x00.toByte()) + bytes
                }
                return byteArrayOf(0x02, bytes.size.toByte()) + bytes.toByteArray()
            }

            val asn1R = asn1Integer(r)
            val asn1S = asn1Integer(s)
            val asn1Sequence = byteArrayOf(0x30) + asn1Length(asn1R.size + asn1S.size) + asn1R + asn1S
            asn1Sequence
        } catch (e: Exception) {
            null // Return null on failure
        }
    }

    private fun base64UrlToBase64(base64Url: String): String {
        var base64 = base64Url.replace('-', '+').replace('_', '/')
        val padding = 4 - base64.length % 4
        if (padding != 4) {
            base64 += "=".repeat(padding)
        }
        return base64
    }

    private fun verifySignature(publicKey: PublicKey, data: ByteArray, signature: ByteArray, algorithm: JWSAlgorithm? = null): Boolean {
        return try {
            // Check if the algorithm is provided or not
            val signatureInstance = if (algorithm != null && algorithm.name.startsWith("ES")) {
                // If the algorithm starts with "ES", it's likely an ECDSA (e.g., ES256)
                Signature.getInstance("SHA256withECDSA")
            } else {
                // Default to RSA algorithm (e.g., RS256, RS512)
                Signature.getInstance("SHA256withRSA")
            }

            // Initialize signature verification with the public key
            signatureInstance.initVerify(publicKey)
            signatureInstance.update(data)
            signatureInstance.verify(signature)
        } catch (e: Exception) {
            println("Signature verification failed: ${e.message}")
            false
        }
    }




    @Throws(Exception::class)
    fun validateTrustChain(x5cCertificates: List<String>): Boolean {
        val cf = CertificateFactory.getInstance("X.509")

        // Convert Base64 strings to X509Certificates
        val x509Certificates = x5cCertificates.map { x5c ->
            val certBytes = base64.getDecoder().decode(x5c)
            cf.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
        }

        // Create a custom KeyStore with the provided certificates as trusted anchors
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null) // Initialize an empty KeyStore
            x509Certificates.forEachIndexed { index, cert ->
                setCertificateEntry("cert$index", cert) // Add each certificate as a trusted entry
            }
        }

        // Initialize TrustManager with the custom KeyStore
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(keyStore)

        // Create CertPath from X509Certificates
        val certPath = cf.generateCertPath(x509Certificates)

        // Configure PKIXParameters to use only the provided anchors
        val params = PKIXParameters(keyStore)
        params.isRevocationEnabled = false // Disable revocation for simplicity

        // Validate CertPath
        val cpv = CertPathValidator.getInstance("PKIX")
        try{
            cpv.validate(certPath, params)
            return true
        }catch (e:Exception){
            println("${e.message}")
            return false
        }

    }

    fun validateClientIDInCertificate(x5cChain: List<String>?, clientID: String?): Boolean {
        if (x5cChain.isNullOrEmpty() || clientID.isNullOrEmpty()) return false

        val scheme = ClientIdParser.getClientIdScheme(clientID) ?: return false
        val identifier = ClientIdParser.getSchemeSpecificIdentifier(clientID) ?: return false

        return try {
            val leafCertData = Base64.decode(x5cChain.first(), Base64.DEFAULT)
            val certificate = CertificateFactory.getInstance("X.509")
                .generateCertificate(leafCertData.inputStream()) as X509Certificate

            val matched = when (scheme) {
                ClientIdScheme.X509_SAN_DNS -> {
                    val dnsNames = extractDNSNamesFromCertificate(certificate)
                    dnsNames.contains(identifier)
                }
                ClientIdScheme.X509_SAN_URI -> {
                    val uriNames = extractUriSANsFromCertificate(certificate)
                    uriNames.any { it.equals(identifier, ignoreCase = true) }
                }
                else -> false
            }

            matched
        } catch (e: Exception) {
            println("Error validating ClientID against SAN: ${e.message}")
            false
        }
    }

    /**
     * Extract URI SAN (Subject Alternative Name) entries (type 6) from the certificate.
     */
    private fun extractUriSANsFromCertificate(certificate: X509Certificate): List<String> {
        val uriSANs = mutableListOf<String>()
        val sanList = certificate.subjectAlternativeNames ?: return uriSANs

        for (san in sanList) {
            if (san[0] == 6) { // 6 = URI per RFC 5280
                uriSANs.add(san[1] as String)
            }
        }
        return uriSANs
    }

}
