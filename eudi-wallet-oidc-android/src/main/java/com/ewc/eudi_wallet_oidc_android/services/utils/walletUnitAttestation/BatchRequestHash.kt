package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation

import com.nimbusds.jose.jwk.JWK
import java.security.MessageDigest
import java.util.Base64

/**
 * Play Integrity request hash for a batch wallet-unit request (#3347):
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
}
