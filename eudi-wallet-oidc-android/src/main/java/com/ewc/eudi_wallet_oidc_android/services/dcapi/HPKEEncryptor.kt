package com.ewc.eudi_wallet_oidc_android.services.dcapi

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class HPKEEncryptionResult(
    val encapsulatedKey: ByteArray,
    val cipherText: ByteArray
)

/**
 * HPKE (RFC 9180) single-shot encryption per ISO 18013-7 Annex C — pure JCA, no BouncyCastle.
 *
 * Cipher suite: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
 * Mode: Base (0x00)
 *
 * Implemented against RFC 9180 §4 (DHKEM), §4.1 (LabeledExtract/Expand), §5.1 (key schedule),
 * §5.2 (seal). Validated against the RFC 9180 Appendix A.3 test vectors (see HPKEEncryptorTest).
 */
object HPKEEncryptor {

    // RFC 9180 algorithm identifiers for this suite
    private val KEM_ID = byteArrayOf(0x00, 0x10)   // DHKEM(P-256, HKDF-SHA256)
    private val KDF_ID = byteArrayOf(0x00, 0x01)   // HKDF-SHA256
    private val AEAD_ID = byteArrayOf(0x00, 0x01)  // AES-128-GCM
    private const val MODE_BASE: Byte = 0x00

    private const val NSECRET = 32  // KEM shared secret length
    private const val NK = 16       // AEAD key length (AES-128)
    private const val NN = 12       // AEAD nonce length
    private const val NH = 32       // HKDF-SHA256 output length

    private const val HPKE_V1 = "HPKE-v1"

    private val kemSuiteId: ByteArray = "KEM".toByteArray(Charsets.US_ASCII) + KEM_ID
    private val hpkeSuiteId: ByteArray =
        "HPKE".toByteArray(Charsets.US_ASCII) + KEM_ID + KDF_ID + AEAD_ID

    fun encrypt(
        plaintext: ByteArray,
        recipientPublicKey: ParsedCOSEKey,
        info: ByteArray
    ): HPKEEncryptionResult {
        try {
            val recipientPoint = recipientPublicKey.toUncompressedPoint()

            // Generate the ephemeral P-256 key pair (skE, pkE)
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
            val ephemeral = kpg.generateKeyPair()
            val encPoint = serializePublicKey(ephemeral.public as ECPublicKey)

            return sealBase(recipientPoint, info, plaintext, ByteArray(0), ephemeral.private, encPoint)
        } catch (e: Exception) {
            throw DCAPIError.HPKEEncryptionFailed(e.message ?: "Unknown error")
        }
    }

    /**
     * Test-only seam: lets the RFC 9180 vector tests inject a fixed ephemeral key (skE/pkE) and aad.
     * Not used in production — [encrypt] always generates a fresh ephemeral key and empty aad.
     */
    internal fun sealBase(
        recipientPointUncompressed: ByteArray,
        info: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray,
        ephemeralPrivate: PrivateKey,
        encPoint: ByteArray
    ): HPKEEncryptionResult {
        val recipientPublic = publicKeyFromPoint(recipientPointUncompressed)

        // --- DHKEM Encap (RFC 9180 §4.1) ---
        val dh = ecdh(ephemeralPrivate, recipientPublic)                 // P-256 DH = X coordinate (32 B)
        val kemContext = encPoint + recipientPointUncompressed           // enc || pkRm
        val sharedSecret = extractAndExpand(dh, kemContext)              // Nsecret bytes

        // --- KeySchedule, mode_base (RFC 9180 §5.1) ---
        val pskIdHash = labeledExtract(ByteArray(0), hpkeSuiteId, "psk_id_hash", ByteArray(0))
        val infoHash = labeledExtract(ByteArray(0), hpkeSuiteId, "info_hash", info)
        val keyScheduleContext = byteArrayOf(MODE_BASE) + pskIdHash + infoHash

        val secret = labeledExtract(sharedSecret, hpkeSuiteId, "secret", ByteArray(0))
        val key = labeledExpand(secret, hpkeSuiteId, "key", keyScheduleContext, NK)
        val baseNonce = labeledExpand(secret, hpkeSuiteId, "base_nonce", keyScheduleContext, NN)

        // --- Seal, sequence number 0 => nonce == base_nonce (RFC 9180 §5.2) ---
        val cipherText = aesGcmSeal(key, baseNonce, aad, plaintext)
        return HPKEEncryptionResult(encPoint, cipherText)
    }

    // ---- DHKEM ----

    private fun extractAndExpand(dh: ByteArray, kemContext: ByteArray): ByteArray {
        val eaePrk = labeledExtract(ByteArray(0), kemSuiteId, "eae_prk", dh)
        return labeledExpand(eaePrk, kemSuiteId, "shared_secret", kemContext, NSECRET)
    }

    private fun ecdh(privateKey: PrivateKey, publicKey: ECPublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(privateKey)
        ka.doPhase(publicKey, true)
        // For P-256 the ECDH shared secret is the X coordinate; normalise to 32 bytes.
        return fixedLength(ka.generateSecret(), 32)
    }

    // ---- Labeled HKDF (RFC 9180 §4) ----

    private fun labeledExtract(
        salt: ByteArray,
        suiteId: ByteArray,
        label: String,
        ikm: ByteArray
    ): ByteArray {
        val labeledIkm = HPKE_V1.toByteArray(Charsets.US_ASCII) +
            suiteId + label.toByteArray(Charsets.US_ASCII) + ikm
        return hkdfExtract(salt, labeledIkm)
    }

    private fun labeledExpand(
        prk: ByteArray,
        suiteId: ByteArray,
        label: String,
        info: ByteArray,
        length: Int
    ): ByteArray {
        val labeledInfo = i2osp(length, 2) + HPKE_V1.toByteArray(Charsets.US_ASCII) +
            suiteId + label.toByteArray(Charsets.US_ASCII) + info
        return hkdfExpand(prk, labeledInfo, length)
    }

    // ---- HKDF-SHA256 (RFC 5869) ----

    private fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
        // Empty salt == NH zero bytes (HMAC zero-pads the key to the block size anyway).
        val key = if (salt.isEmpty()) ByteArray(NH) else salt
        return hmacSha256(key, ikm)
    }

    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val out = ByteArray(length)
        var t = ByteArray(0)
        var pos = 0
        var i = 1
        while (pos < length) {
            t = hmacSha256(prk, t + info + byteArrayOf(i.toByte()))
            val n = minOf(t.size, length - pos)
            System.arraycopy(t, 0, out, pos, n)
            pos += n
            i++
        }
        return out
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    // ---- AEAD ----

    private fun aesGcmSeal(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(plaintext) // ciphertext || 16-byte tag
    }

    // ---- EC helpers ----

    private val p256Params: ECParameterSpec by lazy {
        val params = AlgorithmParameters.getInstance("EC")
        params.init(ECGenParameterSpec("secp256r1"))
        params.getParameterSpec(ECParameterSpec::class.java)
    }

    private fun publicKeyFromPoint(point: ByteArray): ECPublicKey {
        require(point.size == 65 && point[0].toInt() == 0x04) { "Expected 65-byte uncompressed P-256 point" }
        val x = BigInteger(1, point.copyOfRange(1, 33))
        val y = BigInteger(1, point.copyOfRange(33, 65))
        val spec = ECPublicKeySpec(ECPoint(x, y), p256Params)
        return KeyFactory.getInstance("EC").generatePublic(spec) as ECPublicKey
    }

    private fun serializePublicKey(key: ECPublicKey): ByteArray {
        val x = fixedLength(key.w.affineX.toByteArray(), 32)
        val y = fixedLength(key.w.affineY.toByteArray(), 32)
        return byteArrayOf(0x04) + x + y
    }

    // ---- byte utils ----

    private fun i2osp(value: Int, length: Int): ByteArray {
        val out = ByteArray(length)
        var v = value
        for (i in length - 1 downTo 0) {
            out[i] = (v and 0xFF).toByte()
            v = v ushr 8
        }
        return out
    }

    /** Left-trim sign bytes / left-pad with zeros to exactly [length] bytes. */
    private fun fixedLength(value: ByteArray, length: Int): ByteArray {
        if (value.size == length) return value
        val out = ByteArray(length)
        if (value.size > length) {
            System.arraycopy(value, value.size - length, out, 0, length)
        } else {
            System.arraycopy(value, 0, out, length - value.size, value.size)
        }
        return out
    }
}
