package com.ewc.eudi_wallet_oidc_android.services.verification.presentation

import com.ewc.eudi_wallet_oidc_android.services.sdjwt.SDJWTService
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.util.Date
import java.util.UUID

/**
 * The Key Binding JWT of an SD-JWT presentation (SD-JWT VC, OpenID4VP 1.0 Appendix B.3.6).
 *
 * `aud` is the client identifier, `nonce` the request's nonce, `sd_hash` the hash of the
 * presented SD-JWT up to and including its last `~`. OpenID4VP section 8.4 adds
 * `transaction_data_hashes` and `transaction_data_hashes_alg`; the TS12 strong customer
 * authentication profile adds `response_mode` and `amr`.
 */
object KeyBindingJwt {

    const val TYPE = "kb+jwt"
    const val HASH_ALGORITHM = "sha-256"

    /**
     * @param presented the SD-JWT to bind, ending with `~`.
     * @throws PresentationException.KeyBindingFailed
     */
    fun sign(
        entryId: String,
        presented: String,
        key: JWK,
        audience: String?,
        nonce: String?,
        transactionDataHashes: List<String>? = null,
        scaResponseMode: String? = null,
        amr: List<Map<String, String>>? = null,
    ): String {
        try {
            val claims = JWTClaimsSet.Builder()
                .claim("nonce", nonce ?: UUID.randomUUID().toString())
                .claim("aud", audience)
                .claim("iat", Date())
                .claim("sd_hash", SDJWTService().calculateSHA256Hash(presented))
                .claim("jti", UUID.randomUUID().toString())
            scaResponseMode?.let { claims.claim("response_mode", it) }
            amr?.let { claims.claim("amr", it) }
            transactionDataHashes?.takeIf { it.isNotEmpty() }?.let {
                claims.claim("transaction_data_hashes", it)
                claims.claim("transaction_data_hashes_alg", HASH_ALGORITHM)
            }

            val (algorithm, signer) = when (key) {
                is ECKey -> JWSAlgorithm.ES256 to ECDSASigner(key)
                is OctetKeyPair -> JWSAlgorithm.EdDSA to Ed25519Signer(key)
                else -> throw IllegalArgumentException("unsupported key type ${key.keyType}")
            }
            val header = JWSHeader.Builder(algorithm).type(JOSEObjectType(TYPE)).build()
            return SignedJWT(header, claims.build()).apply { sign(signer) }.serialize()
        } catch (e: Exception) {
            throw PresentationException.KeyBindingFailed(entryId, e)
        }
    }
}
