package com.ewc.eudi_wallet_oidc_android.services.utils

import android.util.Log
import org.spongycastle.asn1.ASN1OctetString
import org.spongycastle.asn1.ASN1Primitive
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

object X509SkiGeneratorHelper {

    fun parseCertificateFromBase64(base64Cert: String): X509Certificate? {
        return try {
            val certBytes = Base64.getDecoder().decode(base64Cert)
            val certFactory = CertificateFactory.getInstance("X.509")
            return certFactory.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
        }catch (e: Exception) {
            Log.e("X509SkiGeneratorHelper", "Error parsing certificate: ${e.message}")
            null
        }
    }

    fun generateSkiString(cert: X509Certificate): String? {
        return try {
            val extensionValue = cert.getExtensionValue("2.5.29.14")
            if (extensionValue != null) {
                val asn1 = ASN1Primitive.fromByteArray(extensionValue) as ASN1OctetString
                val ski = ASN1Primitive.fromByteArray(asn1.octets) as ASN1OctetString
                return ski.octets.joinToString("") { "%02X".format(it) }
            }

            // Fallback: SHA-1(public key bytes)
            val publicKeyBytes = cert.publicKey.encoded
            val sha1 = MessageDigest.getInstance("SHA-1")
            val skiBytes = sha1.digest(publicKeyBytes)
            return skiBytes.joinToString("") { "%02X".format(it) }
        }catch (e: Exception) {
            Log.e("X509SkiGeneratorHelper", "Error generating SKI: ${e.message}")
            null
        }
    }
}