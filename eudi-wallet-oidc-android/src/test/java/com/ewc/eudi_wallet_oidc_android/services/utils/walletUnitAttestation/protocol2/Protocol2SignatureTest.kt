package com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.protocol2

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.math.BigInteger

/**
 * The RFC 9421 signature of protocol 2 against the reference test vector of the wallet provider
 * (CONTRACT.md section 2, `test-vector-protocol2.json`, case `android-status`): the same Content-
 * Digest, the same signature base and Signature-Input, the given signature verifies, and the
 * signature of this code verifies with the public key.
 */
class Protocol2SignatureTest {

    private val case: JSONObject = run {
        val text = javaClass.classLoader!!.getResource("protocol2/test-vector-protocol2.json")!!.readText()
        val cases = JSONObject(text).getJSONArray("cases")
        (0 until cases.length()).map { cases.getJSONObject(it) }.first { it.getString("name") == "android-status" }
    }

    private val headers = case.getJSONObject("headers")
    private val jwk = case.getJSONObject("requestKeyPublicJwk")

    private val privateKey: ECKey = ECKey.Builder(
        Curve.P_256,
        Base64URL(jwk.getString("x")),
        Base64URL(jwk.getString("y"))
    ).d(Base64URL.encode(unsigned32(BigInteger(case.getString("requestKeyPrivateScalarHex"), 16)))).build()

    private val requestKey = PrivateKeyRequestKey.of(privateKey)

    private val app = WalletAppIdentity(
        version = headers.getString("X-Wallet-App-Version"),
        build = headers.getString("X-Wallet-App-Build"),
        deviceModel = headers.getString("X-Wallet-Device-Model")
    )

    private val body = case.getString("bodyUtf8").toByteArray(Charsets.UTF_8)

    private fun signed() = Protocol2Headers.sign(
        method = case.getString("method"),
        targetUri = case.getString("targetUri"),
        body = body,
        nonce = headers.getString("X-Wallet-Unit-Nonce"),
        app = app,
        requestKey = requestKey,
        created = case.getLong("created")
    )

    @Test
    fun `keyid is the RFC 7638 thumbprint of the request key`() {
        assertEquals(case.getString("keyid"), requestKey.keyId)
    }

    @Test
    fun `content digest of the body is the one of the vector`() {
        assertEquals(headers.getString("Content-Digest"), ContentDigest.sha256(body))
    }

    @Test
    fun `signature base and Signature-Input are the ones of the vector`() {
        val (out, signature) = signed()
        assertEquals(case.getString("signatureBase"), signature.signatureBase)
        assertEquals(headers.getString("Signature-Input"), out["Signature-Input"])
        for (name in listOf(
            "Content-Type", "Content-Digest", "X-Wallet-Unit-Nonce", "X-Wallet-Unit-Platform",
            "X-Wallet-App-Version", "X-Wallet-App-Build", "X-Wallet-Device-Model"
        )) {
            assertEquals(name, headers.getString(name), out[name])
        }
        val components = case.getJSONArray("coveredComponents")
        assertEquals(
            (0 until components.length()).map { components.getString(it) },
            Protocol2Headers.ANDROID_COMPONENTS
        )
    }

    @Test
    fun `the signature of the vector verifies with its public key`() {
        assertTrue(
            HttpMessageSignature.verify(
                case.getString("signatureBase"),
                case.getString("signatureRawBase64"),
                privateKey.toPublicJWK()
            )
        )
        assertEquals("wp=:" + case.getString("signatureRawBase64") + ":", headers.getString("Signature"))
    }

    @Test
    fun `the signature of this code verifies and has the r s form`() {
        val (out, signature) = signed()
        val value = out.getValue("Signature")
        assertTrue(value.startsWith("wp=:") && value.endsWith(":"))
        val raw = value.removePrefix("wp=:").removeSuffix(":")
        assertEquals(64, java.util.Base64.getDecoder().decode(raw).size)
        assertTrue(HttpMessageSignature.verify(signature.signatureBase, raw, privateKey.toPublicJWK()))
        // Evidence for the cross check with the server code: the headers this code made.
        File("build/protocol2").apply { mkdirs() }.resolve("android-status-signed.json").writeText(
            JSONObject().put("signatureBase", signature.signatureBase).put("headers", JSONObject(out))
                .put("publicJwk", JSONObject(privateKey.toPublicJWK().toJSONString())).toString(2)
        )
    }

    @Test
    fun `a changed covered value does not verify`() {
        val (_, signature) = signed()
        val raw = case.getString("signatureRawBase64")
        assertFalse(
            HttpMessageSignature.verify(
                signature.signatureBase.replace("x-wallet-app-build\": 490", "x-wallet-app-build\": 491"),
                raw,
                privateKey.toPublicJWK()
            )
        )
    }

    @Test
    fun `content digest of an empty JSON object and of a JSON body`() {
        // Values from Python: base64(hashlib.sha256(body).digest()).
        assertEquals("sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:", ContentDigest.sha256("{}".toByteArray()))
        assertEquals(
            "sha-256=:ykEqvRQ01qDR7wg6+ivS/+ZlCp5Wv1/Ie5VT5DM+V4I=:",
            ContentDigest.sha256(
                "{\"client_assertion\":\"eyJ0ZXN0IjoxfQ.e30.c2ln\",\"client_assertion_type\":\"urn:ietf:params:oauth:client-assertion-type:jwt-bearer\"}"
                    .toByteArray()
            )
        )
    }

    private fun unsigned32(value: BigInteger): ByteArray {
        val bytes = value.toByteArray()
        return when {
            bytes.size == 32 -> bytes
            bytes.size > 32 -> bytes.copyOfRange(bytes.size - 32, bytes.size)
            else -> ByteArray(32 - bytes.size) + bytes
        }
    }
}
