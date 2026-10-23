package com.ewc.eudi_wallet_oidc_android.services.verification.client

/**
 * OpenID4VP 1.0 section 5.9: the part of a `client_id` before the first colon, which says how
 * the verifier authenticates its request.
 *
 * The legacy entries are the draft 20 "client id schemes" that 1.0 dropped or renamed; they live
 * here so a request from an older verifier still parses, and their handlers sit under `legacy/`.
 */
enum class ClientIdPrefix(
    /** The text before the colon, or null for a client id with no prefix. */
    val value: String?,
    val legacy: Boolean = false,
) {
    /** The identifier is the redirect or response URI. The request carries no authentication. */
    REDIRECT_URI("redirect_uri"),

    /** The identifier is an OpenID Federation entity identifier. Not implemented. */
    OPENID_FEDERATION("openid_federation"),

    /** The identifier is a DID; the request is signed with a key from its DID document. */
    DECENTRALIZED_IDENTIFIER("decentralized_identifier"),

    /** The request carries a verifier attestation JWT in its `jwt` header. */
    VERIFIER_ATTESTATION("verifier_attestation"),

    /** The identifier is a dNSName SAN of the leaf certificate in the `x5c` header. */
    X509_SAN_DNS("x509_san_dns"),

    /** The identifier is the base64url SHA-256 of the leaf certificate in the `x5c` header. */
    X509_HASH("x509_hash"),

    /** Reserved for the Digital Credentials API audience; section 5.9.3 says a request MUST NOT use it. */
    ORIGIN("origin"),

    /** No prefix, or one this SDK does not recognise: section 5.9.2, a pre-registered client. */
    PRE_REGISTERED(null),

    // --- legacy, draft 20 and earlier ---
    HTTPS("https", legacy = true),
    DID("did", legacy = true),
    X509_SAN_URI("x509_san_uri", legacy = true),
    WEB_ORIGIN("web-origin", legacy = true);

    companion object {
        fun fromValue(value: String?): ClientIdPrefix? =
            value?.let { v -> entries.firstOrNull { it.value == v } }
    }
}
