package com.ewc.eudi_wallet_oidc_android.services.discovery.metadata

import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudi_wallet_oidc_android.services.credentialValidation.SignatureValidator
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.SignedJWT
import java.util.Date

/**
 * Who signed a metadata document, as far as the signature itself can say.
 *
 * Everything here is **self-asserted by the document**. Verifying the signature proves the document
 * was signed by the key named below; it says nothing about whether that key may speak for the
 * issuer. That judgement is [MetadataSignerTrust]'s.
 */
data class SignedMetadataSigner(
    /** The Credential Issuer Identifier the document claims to describe (`sub`). */
    val issuerIdentifier: String,
    /** The JOSE `kid`, often a DID. */
    val keyId: String?,
    /** The JOSE `x5c` chain, leaf first, base64 as received. */
    val x5c: List<String>?,
    /** The `iss` claim, when the signer is not the issuer itself. */
    val issuedBy: String?,
)

/**
 * Decides whether a verified signer may publish metadata for an issuer.
 *
 * This is the "establish trust" half of OpenID4VCI 1.0 section 12.2.3, and the SDK cannot supply
 * it: the spec puts the mechanism out of scope precisely because it is deployment-specific. A
 * host backs this with whatever it already trusts -- an EU Trusted List, a pinned certificate, the
 * trust list services in `services/trust`, or a DID it recognises.
 *
 * Returning `true` unconditionally reduces signed metadata to "signed by someone", which is what
 * the wallet would get from an attacker who can answer the metadata request.
 */
fun interface MetadataSignerTrust {

    suspend fun isTrusted(signer: SignedMetadataSigner): Boolean

    companion object {

        /**
         * Accept any signer whose signature verified. **This is not a trust decision.**
         *
         * The current default, and a deliberate, temporary step: it gets signed metadata working
         * and closes the far worse hole this replaced, where a JWT payload was read and used with
         * no signature check at all. What it still does not do is establish that the verified key
         * may speak for the issuer -- an attacker who can answer the metadata request can sign
         * with their own key, or present their own self-signed certificate in `x5c`, and this
         * accepts it.
         *
         * **Next iteration:** replace with a lookup against
         * [com.ewc.eudi_wallet_oidc_android.services.trust.TrustMechanismService]. Its
         * `isIssuerOrVerifierTrusted(url = ..., x5cChain = ...)` takes exactly what
         * [SignedMetadataSigner] carries:
         *
         * ```kotlin
         * MetadataSignerTrust { signer ->
         *     TrustMechanismService().isIssuerOrVerifierTrusted(
         *         url = signer.issuerIdentifier,
         *         x5cChain = signer.x5c,
         *     )
         * }
         * ```
         *
         * Until then every acceptance is logged so the gap is visible rather than assumed closed.
         */
        @JvmField
        val SignatureOnly = MetadataSignerTrust { signer ->
            Logger.d(
                "MetadataSignerTrust",
                "Accepting signed metadata for ${signer.issuerIdentifier} on signature alone; " +
                    "the signer is not checked against any trust list",
            )
            true
        }
    }
}

/**
 * Verifies signed Credential Issuer Metadata using the SDK's existing [SignatureValidator].
 *
 * [SignatureValidator] already resolves signing keys from every form this SDK meets -- `x5c`, a
 * plain JWK in the header, `did:key`, `did:ebsi`, `did:jwk`, `did:web`, `did:tdw`, `did:webvh`, a
 * `jwks_uri`, and an issuer's own well-known document -- so none of that is re-implemented here.
 *
 * What this class adds is everything section 12.2.3 requires on top of a valid signature:
 *
 *  - `typ` MUST be `openidvci-issuer-metadata+jwt`;
 *  - `alg` MUST NOT be `none` or a symmetric (MAC) algorithm;
 *  - `sub` is REQUIRED and MUST equal the Credential Issuer Identifier the document was fetched for;
 *  - `iat` is REQUIRED, and `exp`, when present, must not have passed;
 *  - and the signer must be **trusted**, not merely authentic.
 *
 * [trust] defaults to [MetadataSignerTrust.SignatureOnly], which accepts any signer whose
 * signature verified. That is **not** the last of the two obligations: [SignatureValidator] answers
 * "was this signed by the key it names?", not "may that key speak for this issuer" -- for an `x5c`
 * chain it checks only that the leaf certificate's public key produced the signature, with no path
 * to any anchor. Supply a real [MetadataSignerTrust] to close it:
 *
 * ```kotlin
 * DiscoveryService(
 *     signedMetadataVerifier = SignatureValidatorSignedMetadataVerifier { signer ->
 *         TrustMechanismService().isIssuerOrVerifierTrusted(
 *             url = signer.issuerIdentifier,
 *             x5cChain = signer.x5c,
 *         )
 *     }
 * )
 * ```
 */
class SignatureValidatorSignedMetadataVerifier(
    private val trust: MetadataSignerTrust = MetadataSignerTrust.SignatureOnly,
    private val signatureValidator: SignatureValidator = SignatureValidator(),
    /** Leeway for `exp`, for clock skew between the wallet and the issuer. */
    private val clockSkewSeconds: Long = 60,
) : SignedMetadataVerifier {

    override val supportsSignedMetadata: Boolean = true

    override suspend fun verify(jwt: String, expectedIssuerIdentifier: String): String {
        val signed = parse(jwt)
        val header = signed.header

        // Header first: `typ` and `alg` decide whether this is a document worth checking at all,
        // and both are covered by the signature, so a mismatch here is not a shortcut.
        //
        // typ: REQUIRED. MUST be openidvci-issuer-metadata+jwt.
        if (!TYPE.equals(header.type?.type, ignoreCase = true)) {
            reject("Its signed configuration is not typed as issuer metadata")
        }

        // alg: MUST NOT be none or an identifier for a symmetric algorithm (MAC).
        val algorithm = header.algorithm
        if (algorithm == null ||
            algorithm == JWSAlgorithm.NONE ||
            JWSAlgorithm.Family.HMAC_SHA.contains(algorithm)
        ) {
            reject("Its signed configuration uses an unacceptable signing algorithm")
        }

        // The signature is checked before any claim is read. Claims from a document whose
        // signature has not been established are attacker-controlled, so nothing is decided on
        // them -- not even which error to report.
        val authentic = try {
            signatureValidator.validateSignature(jwt)
        } catch (e: Exception) {
            Logger.d(TAG, "Signed metadata signature rejected: ${e.message}")
            false
        }
        if (!authentic) reject("Its signed configuration has an invalid signature")

        val claims = try {
            signed.jwtClaimsSet
        } catch (e: Exception) {
            reject("Its signed configuration could not be read")
        }

        // sub: REQUIRED. String matching the Credential Issuer Identifier.
        val subject = claims.subject
        if (subject.isNullOrBlank()) {
            reject("Its signed configuration does not name an issuer")
        }
        if (subject != expectedIssuerIdentifier) {
            reject("Its signed configuration belongs to a different issuer ($subject)")
        }

        // iat: REQUIRED. exp: OPTIONAL, but honoured when present.
        if (claims.issueTime == null) {
            reject("Its signed configuration is not dated")
        }
        claims.expirationTime?.let { expiry ->
            if (Date().after(Date(expiry.time + clockSkewSeconds * 1000))) {
                reject("Its signed configuration has expired")
            }
        }

        val signer = SignedMetadataSigner(
            issuerIdentifier = subject,
            keyId = header.keyID,
            // Read from the parsed JOSE header rather than re-extracting from the raw JWT: the
            // helper in X509SanRequestVerifier goes through android.util.Base64, which is not
            // available off-device, and there is no reason to decode the header twice.
            x5c = header.x509CertChain?.map { it.toString() },
            issuedBy = claims.issuer,
        )
        if (!trust.isTrusted(signer)) {
            reject("Its signed configuration is signed by a party this wallet does not trust")
        }

        Logger.d(TAG, "Accepted signed issuer metadata for $expectedIssuerIdentifier")
        return claims.toPayload().toString()
    }

    private fun parse(jwt: String): SignedJWT {
        // An unsecured JWT has an empty signature. Nimbus rejects `alg: none` on its own, but this
        // is the one check that must not depend on a library's internals.
        if (jwt.substringAfterLast('.').isBlank()) {
            reject("Its signed configuration is unsigned")
        }
        return try {
            SignedJWT.parse(jwt)
        } catch (e: Exception) {
            reject("Its signed configuration could not be read")
        }
    }

    private fun reject(detail: String): Nothing =
        throw DiscoveryException.SignedMetadataRejected(detail)

    private companion object {
        const val TAG = "SignedMetadataVerifier"

        /** Section 12.2.3 / IANA registration G.6.3. */
        const val TYPE = "openidvci-issuer-metadata+jwt"
    }
}
