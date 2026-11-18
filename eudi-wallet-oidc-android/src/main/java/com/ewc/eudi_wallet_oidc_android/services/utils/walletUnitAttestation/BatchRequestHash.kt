package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation

import com.nimbusds.jose.jwk.JWK
import java.security.MessageDigest
import java.util.Base64

/**
 * Play Integrity request hash for a batch wallet-unit request (#3347), and
 * the protocol 2 request binding built on it ([requestBinding]):
 *
 *     base64url(SHA-256(concat(sorted(RFC 7638 thumbprint of each cnf key))))
 *
 * Thumbprints are sorted as plain strings and concatenated with no separator.
 * The wallet provider recomputes the value from the cnf keys it receives and
 * refuses a mismatch. Base64URL without padding, like [generateHash].
 */
object BatchRequestHash {

    fun compute(keys: List<JWK>): String =
        computeFromThumbprints(keys.map { it.computeThumbprint().toString() })

    fun computeFromThumbprints(thumbprints: List<String>): String {
        val joined = thumbprints.sorted().joinToString(separator = "")
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(joined.toByteArray(Charsets.UTF_8))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    /**
     * The request binding of a wallet provider protocol 2 request:
     *
     *     base64url(SHA-256(UTF-8(nonce + "." + batch request hash of keys)))
     *
     * Every piece of device evidence of the request covers it (the Play
     * Integrity nonce and the device signature), so evidence made for one
     * request cannot be replayed on another. The keys per request:
     *
     * - WIA request (single or batch): the cnf key of each client assertion;
     * - status and revocation code: no key, so the hash is of the empty string;
     * - key attestation: the issuer `c_nonce` and the attested keys.
     */
    fun requestBinding(nonce: String, keys: List<JWK>): String {
        val input = nonce + "." + compute(keys.map { it.toPublicJWK() })
        val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }
}
