package com.ewc.eudi_wallet_oidc_android.services.verification

enum class ClientIdScheme(val scheme: String) {
    REDIRECT_URI("redirect_uri"),
    HTTPS("https"),
    DID("did"),
    VERIFIER_ATTESTATION("verifier_attestation"),
    X509_SAN_DNS("x509_san_dns"),
    X509_SAN_URI("x509_san_uri"),
    WEB_ORIGIN("web-origin"),
    IAR("iar");

    companion object {
        fun fromScheme(scheme: String): ClientIdScheme? {
            return entries.find { it.scheme == scheme }
        }
    }
}