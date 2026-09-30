package com.ewc.eudi_wallet_oidc_android.services.issue.credential.proof

/**
 * What a credential request offers as proof of possession (section 8.2).
 *
 * Two shapes, because the issuer's `proof_types_supported` decides which is legal:
 *
 *  - [Jwt] -- one or more `openid4vci-proof+jwt`. More than one is a **batch**: section 8.2's
 *    `proofs` member is an array, each entry signed by its own key, and the issuer returns one
 *    credential per proof. Every proof carries the same `nonce`, `aud` and `iss`.
 *  - [Attestation] -- there is no jwt proof at all. The wallet-provider Key Attestation *is* the
 *    proof, and TS3 section 2.2.2 / Appendix F.3 require it to carry the issuer's `c_nonce`.
 *
 * A sealed type rather than a `List<String>` plus a flag, because "no jwt proofs, use the
 * attestation" and "zero jwt proofs by mistake" are otherwise the same value.
 *
 * Mirrors `CredentialProofs` in the iOS SDK.
 */
sealed class CredentialProofs {

    /** One entry is an ordinary request; several is a batch, one credential expected per entry. */
    data class Jwt(val proofs: List<String>) : CredentialProofs()

    /** The key attestation stands as the proof. Carried so the request body can name it. */
    data class Attestation(val keyAttestation: String) : CredentialProofs()

    /** How many credentials this request expects back. */
    val expectedCredentials: Int
        get() = when (this) {
            is Jwt -> proofs.size.coerceAtLeast(1)
            is Attestation -> 1
        }

    val isBatch: Boolean get() = this is Jwt && proofs.size > 1
}
