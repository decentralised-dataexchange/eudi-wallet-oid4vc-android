package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.protocol2

import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.BatchRequestHash
import com.nimbusds.jose.jwk.JWK
import java.security.MessageDigest
import java.util.Base64

/**
 * The request binding of the wallet provider (`ows.standards.ts3.batch_binding`):
 *
 *     base64url(SHA-256(UTF-8(nonce + "." + batch request hash)))
 *
 * The batch request hash is [BatchRequestHash] of the cnf keys of the request (the sorted RFC 7638
 * thumbprints, concatenated). base64url is without padding. The device evidence binds this value:
 * the nonce of the classic Play Integrity request, and the device signature
 * (`X-Wallet-Unit-Device-Signature`) over its UTF-8 bytes.
 *
 * A request with no cnf key (the status and the revocation code routes) binds the empty set: the
 * batch request hash is then base64url(SHA-256("")).
 */
object RequestBinding {

    fun of(nonce: String, cnfKeys: List<JWK>): String =
        ofHash(nonce, BatchRequestHash.compute(cnfKeys.map { it.toPublicJWK() }))

    fun ofHash(nonce: String, batchRequestHash: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest("$nonce.$batchRequestHash".toByteArray(Charsets.UTF_8))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }
}
