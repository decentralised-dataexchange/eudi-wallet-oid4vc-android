package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation

import com.nimbusds.jose.crypto.impl.ECDSA
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyFactory
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPrivateKeySpec
import java.util.Base64

/**
 * The wallet provider protocol 2 pack (`test-vector-protocol2.json`, case
 * `android-status`, and `examples-protocol2.json`): the server made these
 * requests with its own code, so the signature base must match byte for byte
 * and every signature must verify with the test device key.
 */
class WalletProviderVectorTest {

    // The test device key of the pack. Never use it outside tests.
    private val devicePublic: ECKey = ECKey.Builder(
        Curve.P_256,
        Base64URL("wjk5lWu3smO1SfHPxgj8utTSNaK8PjDOuJ0jQLLhgmM"),
        Base64URL("qyxVsnVhA9rn9HymNjOR_9IROFxBXOKU3ZAfboyUTGw")
    ).build()
    private val devicePrivateScalar = "1f2e3d4c5b6a79881726354453627180a9b8c7d6e5f40312233445566778899a"

    private val base = "https://wallet.example/organisation/6ae0f1a2-c4b6-4e7a-9c1d-2f3e4a5b6c7d/service/wallet-provider"

    private fun headers(nonce: String, digest: String = "sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:") = mapOf(
        "Content-Type" to "application/json",
        "Content-Digest" to digest,
        "X-Wallet-Unit-Nonce" to nonce,
        "X-Wallet-Unit-Platform" to "android",
        "X-Wallet-App-Version" to "2026.12.0",
        "X-Wallet-App-Build" to "490",
        "X-Wallet-Device-Model" to "samsung SM-A125F"
    )

    private fun cnf(x: String, y: String): ECKey = ECKey.Builder(Curve.P_256, Base64URL(x), Base64URL(y)).build()

    private fun verifyRaw(base: String, signatureHeader: String): Boolean {
        val raw = Base64.getDecoder().decode(signatureHeader.removePrefix("wp=:").removeSuffix(":"))
        return verifyDer(base.toByteArray(Charsets.UTF_8), ECDSA.transcodeSignatureToDER(raw))
    }

    private fun verifyDer(data: ByteArray, der: ByteArray): Boolean =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(devicePublic.toECPublicKey())
            update(data)
            verify(der)
        }

    @Test
    fun theKeyIdIsTheThumbprintOfTheDeviceKey() {
        assertEquals("kc_AsxzLRyGU7LlE4hEDy7XLCYZvR77pyE6wfYqHbFI", devicePublic.computeThumbprint().toString())
    }

    @Test
    fun theContentDigestOfAnEmptyObject() {
        assertEquals(
            "sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:",
            HTTPMessageSignature.contentDigest("{}".toByteArray(Charsets.UTF_8))
        )
    }

    @Test
    fun androidStatusSignatureBaseIsRebuiltByteForByteAndVerifies() {
        val params = HTTPMessageSignature.signatureParams(
            WalletProviderClient.COMPONENTS, 1794556800, "kc_AsxzLRyGU7LlE4hEDy7XLCYZvR77pyE6wfYqHbFI"
        )
        assertEquals(
            "(\"@method\" \"@target-uri\" \"content-digest\" \"x-wallet-unit-nonce\" \"x-wallet-unit-platform\" " +
                "\"x-wallet-app-version\" \"x-wallet-app-build\" \"x-wallet-device-model\");created=1794556800;" +
                "keyid=\"kc_AsxzLRyGU7LlE4hEDy7XLCYZvR77pyE6wfYqHbFI\";alg=\"ecdsa-p256-sha256\"",
            params
        )
        val signatureBase = HTTPMessageSignature.signatureBase(
            "POST", "$base/wallet-unit/status", headers("n-7c1f0a9e2b"), WalletProviderClient.COMPONENTS, params
        )
        val expected = "\"@method\": POST\n" +
            "\"@target-uri\": $base/wallet-unit/status\n" +
            "\"content-digest\": sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:\n" +
            "\"x-wallet-unit-nonce\": n-7c1f0a9e2b\n" +
            "\"x-wallet-unit-platform\": android\n" +
            "\"x-wallet-app-version\": 2026.12.0\n" +
            "\"x-wallet-app-build\": 490\n" +
            "\"x-wallet-device-model\": samsung SM-A125F\n" +
            "\"@signature-params\": $params"
        assertEquals(expected, signatureBase)
        assertTrue(verifyRaw(expected, "wp=:lvKXiPAJGyoy3C6/DKcOMtix2087G/IQXlABmU0K0qa60YGQ/aOYmk5vfQR18Gbn55uA+Zj8mGUtQFv7O6H2EQ==:"))
    }

    @Test
    fun aSignatureMadeWithTheTestKeyVerifies() {
        val spec = Curve.P_256.toECParameterSpec()
        val privateKey = KeyFactory.getInstance("EC")
            .generatePrivate(ECPrivateKeySpec(BigInteger(devicePrivateScalar, 16), spec))
        val key = JcaSigningKey(privateKey, devicePublic.toECPublicKey() as ECPublicKey)
        assertEquals("kc_AsxzLRyGU7LlE4hEDy7XLCYZvR77pyE6wfYqHbFI", key.keyId)
        val signed = HTTPMessageSignature.sign(
            "POST", "$base/wallet-unit/status", headers("n-7c1f0a9e2b"), WalletProviderClient.COMPONENTS, 1794556800, key
        )!!
        assertEquals(64, Base64.getDecoder().decode(signed.signature.removePrefix("wp=:").removeSuffix(":")).size)
        assertTrue(verifyRaw(signed.signatureBase, signed.signature))
    }

    @Test
    fun aMissingCoveredHeaderCannotBeSigned() {
        val partial = headers("n").filterKeys { it != "X-Wallet-Device-Model" }
        assertEquals(null, HTTPMessageSignature.signatureBase("POST", base, partial, WalletProviderClient.COMPONENTS, "()"))
    }

    // The request bindings and device signatures of examples-protocol2.json.

    private val cnf1 = cnf("1OlbxUJdwIsKjMUzuISEtK6LRzlLXav7lS3dDHC2TE0", "8HXnrvZEL_Ff3nh6AdrgziPvysOIqwYVrwi2ixkAelo")
    private val cnf2 = cnf("DRkxBvYJtrueC1bAhLNqtSX6NM0_-tCrMu8IjUQoW4Q", "_TGMKwUiPYHKYwqNGeeOunWWGcE8Nd5hf1YYpd4L0Fo")

    private fun assertBindingAndDeviceSignature(binding: String, deviceSignature: String) {
        assertTrue(verifyDer(binding.toByteArray(Charsets.UTF_8), Base64.getUrlDecoder().decode(deviceSignature)))
    }

    @Test
    fun registrationBinding() {
        val binding = BatchRequestHash.requestBinding("0lMVydR0KKSM77lW/WGVjqv4kJw=", listOf(cnf1))
        assertEquals("kC6Z66lJ4uDF1E3rpSKkCG4yxLDyvibcKlSDBzST_8g", binding)
        assertBindingAndDeviceSignature(binding, "MEUCIQDgR9WpqUEwRMpszEZLxMlQze0cN74rFCT_eGoAoU4fuAIgL9a4XkGO3zPwefbjC4glOjRAzKSSSQeBn6bg_yKn02k")
    }

    @Test
    fun laterRequestBinding() {
        val binding = BatchRequestHash.requestBinding("u30M8e5ErKC8wPc5t3uTXxOuwv0=", listOf(cnf1))
        assertEquals("b4zd80M-VTcVqhwxjX4gucXJT0OmtSaU6hfdr1yjVNI", binding)
        assertBindingAndDeviceSignature(binding, "MEUCIA4bbQWz7uJKwSQ6Rm0aEsBwmuXGWCP4MoU4b1zfEqg9AiEAq6RK2Gr6I1ge34plUP35SyuT55-Q0bBNoEFum6Oma_4")
    }

    @Test
    fun batchBinding() {
        val binding = BatchRequestHash.requestBinding("bJsZy5Z7Vj2dlrNBrUqJp0RExvE=", listOf(cnf1, cnf2))
        assertEquals("AFhgeV3RoqK7ZXEjzKvJPuEE1B5kH1hGgYDmQZoOs6A", binding)
        assertBindingAndDeviceSignature(binding, "MEQCIDkxN7RuehYEz3vutni3nR8WJVh8GCbiydhdmKNVu9luAiBntmNvIW8SzZqGQIpk9hoYSxS1codnne5huYBqApKRIg")
    }

    @Test
    fun statusBindingHasNoKeys() {
        val binding = BatchRequestHash.requestBinding("SQ9vHYVxaWxajhdOG7Gcja0z1r0=", emptyList())
        assertEquals("k9nuS8PIfwSuQ8ZT7rq_AaeuYP6qK1OjE9MGd2gsdd4", binding)
        assertBindingAndDeviceSignature(binding, "MEQCIB9o2d3erdb9q_3bRXIWbofJMj3lj_d9X6EqSIEhkJ0-AiBtfsdTL9Ie40IcAbULlvs0yHetrfh8RE8BtBE064MZkQ")
    }

    @Test
    fun keyAttestationBindingCoversTheAttestedKeys() {
        val keys = listOf(
            cnf("7kyzVZaqLGCkdTnfciO26SOC0yOzZVz2l8MTc_7umo8", "8tQwIbR3Vjfsvz95StTeM9ijsvYJk5nppmyMcXX6b-k"),
            cnf("GSS8ABq6Td5PPYJ3O6oJgcEqbmhtbZHW376JU-c5cl8", "p19ceQaXsVgEde_eY9DSWdfcU4VfL1sTz3mYWh14hL8")
        )
        val binding = BatchRequestHash.requestBinding("issuer-c-nonce-3f9a1b7c", keys)
        assertEquals("gNqd5eju0PdSWQdX0T0vLGqWGwpvgg-XragO_hxs8Ew", binding)
        assertBindingAndDeviceSignature(binding, "MEUCIQDmX1oj2xexbYBaPsUqHaQgtbTJ8p5kTuH3xqh2Y1zp9wIgURsNTG8_vcV0oW59neGD1mm7qKZlypZkfKfjUQANFjI")
    }

    @Test
    fun theWalletProviderBaseAlwaysEndsWithWalletProvider() {
        val service = "https://wallet.example/organisation/1/service"
        assertEquals("$service/wallet-provider", WalletProviderClient.walletProviderBase(service))
        assertEquals("$service/wallet-provider", WalletProviderClient.walletProviderBase("$service/"))
        assertEquals("$service/wallet-provider", WalletProviderClient.walletProviderBase("$service/wallet-provider/"))
    }
}
