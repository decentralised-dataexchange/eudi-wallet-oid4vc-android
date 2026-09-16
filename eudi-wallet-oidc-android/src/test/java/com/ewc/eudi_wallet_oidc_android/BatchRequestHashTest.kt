package com.ewc.eudi_wallet_oidc_android

import com.ewc.eudi_wallet_oidc_android.services.utils.generateHash
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.BatchRequestHash
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

/**
 * The batch wallet-unit request hash (#3347):
 * base64url(SHA-256(concat(sorted(RFC 7638 thumbprints)))), no padding.
 * The wallet provider recomputes it, so every detail here (thumbprint
 * canonical form, sort order, no separator, no padding) is wire contract.
 */
class BatchRequestHashTest {

    // RFC 7515 Appendix A.3 P-256 public key.
    private val keyA: ECKey = ECKey.Builder(
        Curve.P_256,
        Base64URL("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"),
        Base64URL("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
    ).build()

    // RFC 7517 Appendix A.1 P-256 public key.
    private val keyB: ECKey = ECKey.Builder(
        Curve.P_256,
        Base64URL("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"),
        Base64URL("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")
    ).build()

    private fun sha256B64Url(input: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
        )

    private fun rfc7638(key: ECKey): String =
        sha256B64Url("""{"crv":"P-256","kty":"EC","x":"${key.x}","y":"${key.y}"}""")

    @Test
    fun `nimbus thumbprint matches the RFC 7638 canonical form`() {
        assertEquals(rfc7638(keyA), keyA.computeThumbprint().toString())
        assertEquals(rfc7638(keyB), keyB.computeThumbprint().toString())
    }

    @Test
    fun `hash is independent of key order`() {
        assertEquals(
            BatchRequestHash.compute(listOf(keyA, keyB)),
            BatchRequestHash.compute(listOf(keyB, keyA))
        )
    }

    @Test
    fun `hash equals sha256 of the sorted thumbprints joined with no separator`() {
        val expected = sha256B64Url(listOf(rfc7638(keyA), rfc7638(keyB)).sorted().joinToString(""))
        assertEquals(expected, BatchRequestHash.compute(listOf(keyA, keyB)))
    }

    @Test
    fun `single key hash equals generateHash over its thumbprint`() {
        assertEquals(generateHash(rfc7638(keyA)), BatchRequestHash.compute(listOf(keyA)))
    }

    @Test
    fun `output is base64url without padding`() {
        val hash = BatchRequestHash.compute(listOf(keyA, keyB))
        assertEquals(43, hash.length)
        assertTrue(hash.matches(Regex("^[A-Za-z0-9_-]{43}$")))
    }

    @Test
    fun `thumbprints are sorted by code point`() {
        // '-' (0x2D) < 'A' (0x41) < '_' (0x5F) < 'b' (0x62)
        assertEquals(
            sha256B64Url("-A_b"),
            BatchRequestHash.computeFromThumbprints(listOf("b", "A", "_", "-"))
        )
    }

    @Test
    fun `different key sets give different hashes`() {
        assertNotEquals(
            BatchRequestHash.compute(listOf(keyA)),
            BatchRequestHash.compute(listOf(keyA, keyB))
        )
    }
}
