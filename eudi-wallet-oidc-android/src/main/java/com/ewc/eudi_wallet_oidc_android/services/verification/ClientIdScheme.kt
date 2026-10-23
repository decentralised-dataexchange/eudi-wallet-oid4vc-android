package com.ewc.eudi_wallet_oidc_android.services.verification

@Deprecated("OpenID4VP 1.0 calls these prefixes; use ClientIdPrefix", ReplaceWith("ClientIdPrefix", "com.ewc.eudi_wallet_oidc_android.services.verification.client.ClientIdPrefix"))
enum class ClientIdScheme(val scheme: String) {
    REDIRECT_URI("redirect_uri"),
    HTTPS("https"),
    DID("did"),
    VERIFIER_ATTESTATION("verifier_attestation"),
    X509_SAN_DNS("x509_san_dns"),
    X509_SAN_URI("x509_san_uri"),
    WEB_ORIGIN("web-origin"),
    IAR("iar"),
    x509_hash("x509_hash"),
    DECENTRALIZED_IDENTIFIER("decentralized_identifier");

    companion object {
        fun fromScheme(scheme: String): ClientIdScheme? {
            return entries.find { it.scheme == scheme }
        }
    }
}