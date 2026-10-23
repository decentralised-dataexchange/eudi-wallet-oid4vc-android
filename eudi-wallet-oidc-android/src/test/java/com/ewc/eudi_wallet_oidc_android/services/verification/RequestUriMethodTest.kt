package com.ewc.eudi_wallet_oidc_android.services.verification

import com.ewc.eudi_wallet_oidc_android.services.verification.request.RequestUriMethod
import com.google.gson.JsonParser
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.jwk.ECKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** OpenID4VP 1.0 section 5.10: Request URI Method `post`. */
class RequestUriMethodTest {

    private val base = "openid4vp://?request_uri=https%3A%2F%2Fverifier.example%2Freq%2F1&client_id=x509_san_dns%3Averifier.example"

    @Test
    fun `post is used only when request_uri_method is post`() {
        assertTrue(RequestUriMethod.isPost("$base&request_uri_method=post"))
        assertTrue(RequestUriMethod.isPost("$base&request_uri_method=POST"))
        assertFalse(RequestUriMethod.isPost("$base&request_uri_method=get"))
        assertFalse(RequestUriMethod.isPost(base))
        assertFalse(RequestUriMethod.isPost("not a uri"))
    }

    @Test
    fun `wallet nonce is fresh and url safe`() {
        val a = RequestUriMethod.newWalletNonce()
        val b = RequestUriMethod.newWalletNonce()
        assertNotEquals(a, b)
        assertTrue(a.matches(Regex("^[A-Za-z0-9_-]{43}$")))
    }

    @Test
    fun `request object must echo the nonce the wallet sent`() {
        assertTrue(RequestUriMethod.nonceAccepted(sent = null, received = null))
        assertTrue(RequestUriMethod.nonceAccepted(sent = null, received = "anything"))
        assertTrue(RequestUriMethod.nonceAccepted(sent = "n1", received = "n1"))
        assertFalse(RequestUriMethod.nonceAccepted(sent = "n1", received = null))
        assertFalse(RequestUriMethod.nonceAccepted(sent = "n1", received = "n2"))
    }

    @Test
    fun `wallet metadata advertises the formats and prefixes the sdk supports`() {
        val json = JsonParser.parseString(RequestUriMethod.walletMetadata()).asJsonObject
        val formats = json.getAsJsonObject("vp_formats_supported")
        assertEquals("ES256", formats.getAsJsonObject("dc+sd-jwt").getAsJsonArray("sd-jwt_alg_values")[0].asString)
        assertEquals(-7, formats.getAsJsonObject("mso_mdoc").getAsJsonArray("deviceauth_alg_values")[0].asInt)
        assertTrue(json.getAsJsonArray("client_id_prefixes_supported").any { it.asString == "x509_san_dns" })
        assertTrue(json.getAsJsonArray("response_modes_supported").any { it.asString == "direct_post.jwt" })
        assertFalse(json.has("jwks"))
    }

    @Test
    fun `wallet metadata carries only the public half of the encryption key`() {
        val key = RequestUriMethod.newEncryptionKey()
        val json = JsonParser.parseString(RequestUriMethod.walletMetadata(key)).asJsonObject
        val jwk = json.getAsJsonObject("jwks").getAsJsonArray("keys")[0].asJsonObject
        assertEquals("EC", jwk.get("kty").asString)
        assertEquals("enc", jwk.get("use").asString)
        assertEquals(key.keyID, jwk.get("kid").asString)
        assertFalse(jwk.has("d"))
        val algs = json.getAsJsonArray("request_object_encryption_alg_values_supported").map { it.asString }
        assertTrue(algs.containsAll(listOf("ECDH-ES", "ECDH-ES+A256KW")))
        assertTrue(json.getAsJsonArray("request_object_encryption_enc_values_supported").any { it.asString == "A128GCM" })
    }

    @Test
    fun `an encrypted request object is opened with the fetch key`() {
        val key = RequestUriMethod.newEncryptionKey()
        val signedRequest = "eyJhbGciOiJFUzI1NiJ9.eyJ3YWxsZXRfbm9uY2UiOiJuMSJ9.c2ln"
        val publicKey = ECKey.parse(JsonParser.parseString(RequestUriMethod.walletMetadata(key)).asJsonObject
            .getAsJsonObject("jwks").getAsJsonArray("keys")[0].toString())
        val jwe = JWEObject(
            JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM).keyID(key.keyID).build(),
            Payload(signedRequest)
        ).apply { encrypt(ECDHEncrypter(publicKey)) }.serialize()

        assertEquals(signedRequest, RequestUriMethod.unwrapEncrypted(jwe, key))
        // A verifier may pick the key-wrap variant, as the SCA payment verifier did on 2026-10-13.
        val jweKeyWrap = JWEObject(
            JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM).keyID(key.keyID).build(),
            Payload(signedRequest)
        ).apply { encrypt(ECDHEncrypter(publicKey)) }.serialize()
        assertEquals(signedRequest, RequestUriMethod.unwrapEncrypted(jweKeyWrap, key))
        assertEquals(signedRequest, RequestUriMethod.unwrapEncrypted(signedRequest, key))
        assertNull(RequestUriMethod.unwrapEncrypted(jwe, RequestUriMethod.newEncryptionKey()))
    }
}

class RequestUriMethodQueryTest {
    @Test
    fun `request_uri is read and percent decoded the way android Uri did it`() {
        val uri = "openid4vp://?client_id=x509_san_dns%3Averifier.example&request_uri=https%3A%2F%2Fverifier.example%2Freq%2F1%3Fa%3Db%26c%3Dd&request_uri_method=post"
        assertEquals("https://verifier.example/req/1?a=b&c=d", RequestUriMethod.requestUri(uri))
        assertNull(RequestUriMethod.requestUri("openid4vp://?client_id=x"))
        assertNull(RequestUriMethod.requestUri("openid4vp://?request_uri="))
    }
}
