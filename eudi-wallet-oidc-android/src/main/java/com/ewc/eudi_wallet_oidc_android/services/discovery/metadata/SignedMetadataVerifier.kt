package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata

/**
 * Establishes trust in signed Credential Issuer Metadata.
 *
 * OpenID4VCI 1.0 section 12.2.3 allows an issuer to return its metadata as a JWT with media type
 * `application/jwt`, and is unambiguous about the obligation that comes with reading one:
 *
 * > When requesting signed metadata, the Wallet MUST establish trust in the signer of the
 * > metadata. Otherwise, the Wallet MUST reject the signed metadata.
 *
 * The SDK cannot do that on its own -- the spec says the mechanism for obtaining the signing key
 * (`x5c`, `kid`, `trust_chain`, ...) is out of scope -- so the default implementation rejects, and
 * a host that has a trust anchor supplies its own.
 *
 * An implementation MUST check all of the following before returning a payload:
 *  - the signature verifies against a key the host trusts;
 *  - `alg` is neither `none` nor a symmetric (MAC) algorithm;
 *  - `typ` is `openidvci-issuer-metadata+jwt`;
 *  - `sub` equals the Credential Issuer Identifier the document was fetched for;
 *  - `iat` is present, and `exp` if present has not passed.
 */
interface SignedMetadataVerifier {

    /**
     * Whether the wallet can verify signed metadata.
     *
     * Drives the `Accept` header: a wallet that cannot verify a signature must not advertise
     * `application/jwt`, because section 12.2.2 treats the Accept header as "signaling whether it
     * supports signed metadata".
     */
    val supportsSignedMetadata: Boolean

    /**
     * @param jwt the compact JWS exactly as received.
     * @param expectedIssuerIdentifier the identifier the metadata was fetched for; `sub` must equal it.
     * @return the verified JWS payload as JSON.
     * @throws DiscoveryException.SignedMetadataRejected when trust cannot be established.
     */
    suspend fun verify(jwt: String, expectedIssuerIdentifier: String): String
}

/**
 * The default: refuse signed metadata rather than read it unverified.
 *
 * Before this existed the SDK decoded the JWT payload and used it as configuration with no
 * signature check at all -- and the JWT helper it used accepts `alg: none` -- so anyone able to
 * serve the metadata response could choose the `credential_endpoint` the wallet then posted
 * credential requests to. Rejecting is the conformant behaviour and strictly safer.
 */
class RejectingSignedMetadataVerifier : SignedMetadataVerifier {

    override val supportsSignedMetadata: Boolean = false

    override suspend fun verify(jwt: String, expectedIssuerIdentifier: String): String =
        throw DiscoveryException.SignedMetadataRejected(
            "This issuer returned signed configuration, which this wallet cannot verify"
        )
}
