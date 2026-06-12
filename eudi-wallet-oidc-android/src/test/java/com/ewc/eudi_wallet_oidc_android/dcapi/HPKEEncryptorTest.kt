package com.ewc.eudi_wallet_oidc_android.dcapi

import com.ewc.eudi_wallet_oidc_android.services.dcapi.HPKEEncryptor
import org.junit.Assert.assertEquals
import org.junit.Test
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec

/**
 * Validates the pure-JCA [HPKEEncryptor] against the official RFC 9180 Appendix A.3.1 test vectors:
 * DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, mode Base.
 *
 * The fixed ephemeral key (skEm) and aad from the RFC are injected via the internal seam so that
 * the output is fully deterministic and can be checked byte-for-byte against the RFC's enc and ct.
 */
class HPKEEncryptorTest {

    // RFC 9180 A.3.1
    private val info = hex("4f6465206f6e2061204772656369616e2055726e")
    private val skEm = hex("4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb")
    private val pkEm = hex(
        "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325a" +
        "c98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"
    )
    private val pkRm = hex(
        "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a" +
        "826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0"
    )
    // A.3.1.1, sequence number 0
    private val pt = hex("4265617574792069732074727574682c20747275746820626561757479")
    private val aad = hex("436f756e742d30")
    private val ct = hex(
        "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f" +
        "9076ac232e3ab2523f39513434"
    )

    @Test
    fun matchesRfc9180A31BaseVector() {
        val ephemeralPrivate = ecPrivateKeyFromScalar(skEm)

        val result = HPKEEncryptor.sealBase(
            recipientPointUncompressed = pkRm,
            info = info,
            plaintext = pt,
            aad = aad,
            ephemeralPrivate = ephemeralPrivate,
            encPoint = pkEm
        )

        assertEquals("enc mismatch", pkEm.toHex(), result.encapsulatedKey.toHex())
        assertEquals("ciphertext mismatch", ct.toHex(), result.cipherText.toHex())
    }

    private fun ecPrivateKeyFromScalar(scalar: ByteArray): java.security.PrivateKey {
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        val spec = ECPrivateKeySpec(BigInteger(1, scalar), params)
        return KeyFactory.getInstance("EC").generatePrivate(spec)
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte() }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
