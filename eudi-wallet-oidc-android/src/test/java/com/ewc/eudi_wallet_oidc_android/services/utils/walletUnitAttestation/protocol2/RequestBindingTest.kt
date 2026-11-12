package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.protocol2

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The request binding is the value of the server function
 * `ows.standards.ts3.batch_binding.request_binding`. The expected values come from that function
 * (organisation-wallet-suite 28fde5c5f), run with the same nonce and keys.
 */
class RequestBindingTest {

    private val keyA = ECKey.Builder(
        Curve.P_256,
        Base64URL("wjk5lWu3smO1SfHPxgj8utTSNaK8PjDOuJ0jQLLhgmM"),
        Base64URL("qyxVsnVhA9rn9HymNjOR_9IROFxBXOKU3ZAfboyUTGw")
    ).build()

    private val keyB = ECKey.Builder(
        Curve.P_256,
        Base64URL("faEG3Kbj1y_SVWKX59GgL_bVttCjiH9URC8OV_3Yp68"),
        Base64URL("HkRfkmW_Yr5N9dc9lD8Hh26QngNaG0YJfNEnRin-1Lk")
    ).build()

    private val nonce = "n-7c1f0a9e2b"

    @Test
    fun `one cnf key gives the binding of the server`() {
        assertEquals("zxbNpUaeiNBAfmPCq9SKynfcJQR9_YUPpYICCg7OLkw", RequestBinding.of(nonce, listOf(keyA)))
    }

    @Test
    fun `two cnf keys in any order give the binding of the server`() {
        assertEquals("sa38E2Tu4Ipg9ARSVIF9pEYWpiYbVgDqSfNHroBstt8", RequestBinding.of(nonce, listOf(keyB, keyA)))
        assertEquals("sa38E2Tu4Ipg9ARSVIF9pEYWpiYbVgDqSfNHroBstt8", RequestBinding.of(nonce, listOf(keyA, keyB)))
    }

    @Test
    fun `no cnf key binds the empty set`() {
        assertEquals("OeYiv2HFdSizmX4SERrny8uMPoMFHW9tOQKIiFe4Q8M", RequestBinding.of(nonce, emptyList()))
        assertEquals(
            "OeYiv2HFdSizmX4SERrny8uMPoMFHW9tOQKIiFe4Q8M",
            RequestBinding.ofHash(nonce, "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU")
        )
    }

    @Test
    fun `a private key gives the same binding as its public key`() {
        val generated = com.nimbusds.jose.jwk.gen.ECKeyGenerator(Curve.P_256).generate()
        assertEquals(
            RequestBinding.of(nonce, listOf(generated.toPublicJWK())),
            RequestBinding.of(nonce, listOf(generated))
        )
    }

    @Test
    fun `the binding is base64url without padding`() {
        val binding = RequestBinding.of(nonce, listOf(keyA))
        assertEquals(43, binding.length)
        assert(binding.none { it == '=' || it == '+' || it == '/' })
    }
}
