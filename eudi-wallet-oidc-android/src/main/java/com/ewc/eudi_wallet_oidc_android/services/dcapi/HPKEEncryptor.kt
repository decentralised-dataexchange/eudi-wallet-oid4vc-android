package com.ewc.eudi_wallet_oidc_android.services.dcapi

import org.bouncycastle.crypto.hpke.HPKE

data class HPKEEncryptionResult(
    val encapsulatedKey: ByteArray,
    val cipherText: ByteArray
)

/**
 * HPKE encryption per ISO 18013-7 Annex C using BouncyCastle.
 *
 * Cipher suite: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
 * Mode: Base (0x00)
 */
object HPKEEncryptor {

    fun encrypt(
        plaintext: ByteArray,
        recipientPublicKey: ParsedCOSEKey,
        info: ByteArray
    ): HPKEEncryptionResult {
        try {
            val hpke = HPKE(
                HPKE.mode_base,
                HPKE.kem_P256_SHA256,
                HPKE.kdf_HKDF_SHA256,
                HPKE.aead_AES_GCM128
            )

            val recipientPubKeyBytes = recipientPublicKey.toUncompressedPoint()
            val recipientKey = hpke.deserializePublicKey(recipientPubKeyBytes)

            val senderContext = hpke.setupBaseS(recipientKey, info)

            val enc = senderContext.encapsulation
            val cipherText = senderContext.seal(ByteArray(0), plaintext)

            return HPKEEncryptionResult(enc, cipherText)
        } catch (e: Exception) {
            throw DCAPIError.HPKEEncryptionFailed(e.message ?: "Unknown error")
        }
    }
}
