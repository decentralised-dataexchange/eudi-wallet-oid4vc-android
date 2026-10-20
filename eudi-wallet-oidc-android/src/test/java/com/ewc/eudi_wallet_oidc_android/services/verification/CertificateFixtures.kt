package com.ewc.eudi_wallet_oidc_android.services.verification

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.PKCS8EncodedKeySpec

/**
 * Two self-signed P-256 certificates made with openssl, each with a SAN DNS name and an
 * AuthorityKeyIdentifier, embedded so the tests need no certificate library.
 */
internal object CertificateFixtures {

    const val VERIFIER_CERT = "MIIBtDCCAVqgAwIBAgIUJsHYk3yflYWvq1iMKQKZITaGXIQwCgYIKoZIzj0EAwIwHzEdMBsGA1UEAwwUdmVyaWZpZXIuZXhhbXBsZS5jb20wHhcNMjYxMDIwMDU0MjEwWhcNMzYxMDE3MDU0MjEwWjAfMR0wGwYDVQQDDBR2ZXJpZmllci5leGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAmSPckSvx36gEW3IKXyZ9fX9N9REqXleT5RzS4OKDfKbBXyDVwlIA3iUNK5FK54huYlgswh65xLhcb4soOYp9ujdDByMB0GA1UdDgQWBBTrdRmNpoBdgt9thiqmS6pm8gU3mzAfBgNVHSMEGDAWgBTrdRmNpoBdgt9thiqmS6pm8gU3mzAPBgNVHRMBAf8EBTADAQH/MB8GA1UdEQQYMBaCFHZlcmlmaWVyLmV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCICHQGvDmhX66OgAgmLUIZmCbkf5Ws/g53LvI/BRK6UblAiEA15PjCV0JkOBonBi8kp9mUFpXfkYokVh1NpOUbZ158sI="
    const val VERIFIER_KEY = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQ3tsfM3VYgHPq49oU/PEM8vl9l8L+pb13hYi/xbP+8KhRANCAAQJkj3JEr8d+oBFtyCl8mfX1/TfURKl5Xk+Uc0uDig3ymwV8g1cJSAN4lDSuRSueIbmJYLMIeucS4XG+LKDmKfb"
    const val OTHER_CERT = "MIIBqzCCAVGgAwIBAgIUDujcZ42n4HZztprdLsAJpk05aoYwCgYIKoZIzj0EAwIwHDEaMBgGA1UEAwwRb3RoZXIuZXhhbXBsZS5jb20wHhcNMjYxMDIwMDU0MjEwWhcNMzYxMDE3MDU0MjEwWjAcMRowGAYDVQQDDBFvdGhlci5leGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJdaY8MDrGB0QpcAdOnDuj6e8vu6Ydd5iXWabud9yB/Geu1I36U4kZDaY0W5RdTPX56hDimKCWLwbQfG71dX01qjcTBvMB0GA1UdDgQWBBTiZSd2e9ah24O5ysEIMuHyJN1mxzAfBgNVHSMEGDAWgBTiZSd2e9ah24O5ysEIMuHyJN1mxzAPBgNVHRMBAf8EBTADAQH/MBwGA1UdEQQVMBOCEW90aGVyLmV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIB0uPVnd6x0zLMf79waHQbk+rUUjtVn8LDBWAwfyaeAuAiEA6Chrffd3laKaEllVaTsYkgyklfiidi+I9d+DdmARaeE="
    const val OTHER_KEY = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZLEeToyJC2WGlj+DmG2+R59t3hsYKHkrmDqkZGBaE5ShRANCAASXWmPDA6xgdEKXAHTpw7o+nvL7umHXeYl1mm7nfcgfxnrtSN+lOJGQ2mNFuUXUz1+eoQ4pigli8G0Hxu9XV9Na"

    fun certificate(b64: String): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(Base64.from(b64).decode())) as X509Certificate

    fun key(certB64: String, keyB64: String): ECKey {
        val cert = certificate(certB64)
        val private = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(Base64.from(keyB64).decode()))
        return ECKey.Builder(Curve.P_256, cert.publicKey as ECPublicKey).privateKey(private).build()
    }

    val verifierCert: X509Certificate by lazy { certificate(VERIFIER_CERT) }
    val otherCert: X509Certificate by lazy { certificate(OTHER_CERT) }
    val verifierKey: ECKey by lazy { key(VERIFIER_CERT, VERIFIER_KEY) }
    val otherKey: ECKey by lazy { key(OTHER_CERT, OTHER_KEY) }
}
